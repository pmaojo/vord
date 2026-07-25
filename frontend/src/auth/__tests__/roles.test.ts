import { describe, it, expect } from 'vitest';
import { permissionsFor, roleHas, ROLES, type Permission, type Role } from '../roles';

describe('RBAC — permissionsFor', () => {
  it('admin gets every permission', () => {
    const perms = permissionsFor(['admin']);
    const expected: Permission[] = [
      'adminAccess', 'browseIssues', 'manageQualityGates',
      'manageProfiles', 'submitAnalyses', 'transitionIssues',
    ];
    for (const p of expected) expect(perms.has(p)).toBe(true);
  });

  it('developer gets all permissions except adminAccess', () => {
    const perms = permissionsFor(['developer']);
    expect(perms.has('adminAccess')).toBe(false);
    expect(perms.has('browseIssues')).toBe(true);
    expect(perms.has('manageQualityGates')).toBe(true);
    expect(perms.has('manageProfiles')).toBe(true);
    expect(perms.has('submitAnalyses')).toBe(true);
    expect(perms.has('transitionIssues')).toBe(true);
  });

  it('viewer is read-only (browse only)', () => {
    const perms = permissionsFor(['viewer']);
    expect(perms.has('browseIssues')).toBe(true);
    expect(perms.has('adminAccess')).toBe(false);
    expect(perms.has('submitAnalyses')).toBe(false);
    expect(perms.has('transitionIssues')).toBe(false);
  });

  it('scanner can only submit analyses (CI service account)', () => {
    const perms = permissionsFor(['scanner']);
    expect(perms.has('submitAnalyses')).toBe(true);
    expect(perms.has('browseIssues')).toBe(false);
    expect(perms.has('transitionIssues')).toBe(false);
  });

  it('multiple roles union permissions', () => {
    // a developer-scanner service account should be able to submit AND browse
    const perms = permissionsFor(['developer', 'scanner']);
    expect(perms.has('submitAnalyses')).toBe(true);
    expect(perms.has('browseIssues')).toBe(true);
  });

  it('empty role list grants no permissions', () => {
    const perms = permissionsFor([]);
    expect(perms.size).toBe(0);
  });

  it('unknown role is safely ignored (unknown role names may exist during migration)', () => {
    const perms = permissionsFor(['admin', 'totally-unknown-role' as unknown as Role]);
    expect(perms.has('adminAccess')).toBe(true);
  });
});

describe('RBAC — roleHas shortcut', () => {
  it('returns true when permission is granted', () => {
    expect(roleHas(['admin'], 'adminAccess')).toBe(true);
  });

  it('returns false when permission is not granted', () => {
    expect(roleHas(['viewer'], 'submitAnalyses')).toBe(false);
  });

  it('ROLES is a non-empty tuple used as <option> source', () => {
    expect(ROLES.length).toBeGreaterThan(0);
    expect(ROLES).toContain('admin');
    expect(ROLES).toContain('developer');
  });
});
