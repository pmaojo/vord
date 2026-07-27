// ---------------------------------------------------------------------------
// RBAC: Roles & Permissions
// ---------------------------------------------------------------------------
// Single source of truth for what each role can do. The backend mirrors this
// map in `bin/server/src/auth.rs` (`Permission` / `permissions_for`); both
// sides MUST agree on the same permission keys — drift is an integration bug,
// not a frontend/UI choice.

// Deliberately small. Add a new role + map before using it anywhere; do not
// introduce permissions ad-hoc in components.
export type Role = 'admin' | 'developer' | 'viewer' | 'scanner';

export const ROLES: readonly Role[] = ['admin', 'developer', 'viewer', 'scanner'] as const;

/** Stable permission keys. Backend and frontend both ship this exact set. */
export type Permission =
  | 'adminAccess'        // /admin, manage users/settings
  | 'browseIssues'       // read issues + projects
  | 'manageQualityGates' // edit QG conditions
  | 'manageProfiles'     // edit quality profile rules
  | 'submitAnalyses'     // POST /api/scans (CI / scanner role)
  | 'transitionIssues';  // confirm/resolve/assign issues

/** Map a role to the permissions it grants. Admin always implies all. */
const ADMIN_GRANTS: readonly Permission[] = [
  'adminAccess',
  'browseIssues',
  'manageQualityGates',
  'manageProfiles',
  'submitAnalyses',
  'transitionIssues',
];

const PERMISSIONS_BY_ROLE: Record<Role, readonly Permission[]> = {
  admin: ADMIN_GRANTS,
  developer: ['browseIssues', 'manageQualityGates', 'manageProfiles', 'submitAnalyses', 'transitionIssues'],
  viewer: ['browseIssues'],
  scanner: ['submitAnalyses'],
};

/** Compute the full permission set for the given roles (admin is a superset). */
export function permissionsFor(roles: readonly Role[]): Set<Permission> {
  const out = new Set<Permission>();
  for (const role of roles) {
    for (const perm of PERMISSIONS_BY_ROLE[role] ?? []) {
      out.add(perm);
    }
  }
  // Defense in depth: admin grant set explicitly added so even if someone
  // trimmed the map accidentally, an admin never loses adminAccess.
  if (out.has('adminAccess')) {
    for (const p of ADMIN_GRANTS) out.add(p);
  }
  return out;
}

/** Returns true if `roles` covers the given permission. */
export function roleHas(roles: readonly Role[], permission: Permission): boolean {
  return permissionsFor(roles).has(permission);
}
