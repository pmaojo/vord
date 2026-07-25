import React, { useState } from 'react';
import { NavLink, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../auth/AuthProvider';
import { usePermission } from '../../auth/usePermission';
import { PermissionGate } from '../../auth/PermissionGate';
import { useGlobalStore } from '../../stores/global-store';
import {
  Search,
  HelpCircle,
  User,
  ChevronDown,
  LogOut,
} from 'lucide-react';
import { cn } from '../../lib/utils';

export const TopNavbar: React.FC = () => {
  const { setSearchOpen } = useGlobalStore();
  const { isAuthenticated, user, logout } = useAuth();
  const canManageQualityGates = usePermission('manageQualityGates');
  const canManageProfiles = usePermission('manageProfiles');
  const navigate = useNavigate();
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);

  // Role-gated navigation. Administration is admin-only; Quality Profiles +
  // Quality Gates are admin + developer. Viewer/scanner see only read views.
  const navItems = [
    { label: 'Overview', path: '/landing' },
    { label: 'Projects', path: '/projects' },
    { label: 'Issues', path: '/issues' },
    { label: 'Rules', path: '/rules' },
    { label: 'Administration', path: '/admin', permission: 'adminAccess' as const },
  ];

  const handleLogout = () => {
    setUserDropdownOpen(false);
    logout();
    navigate('/landing');
  };

  return (
    <header className="bg-[#233445] text-white border-b border-[#1c2a38] sticky top-0 z-40 shadow-xs select-none h-12 flex items-center">
      <div className="max-w-7xl mx-auto px-4 w-full h-full flex items-center justify-between">
        {/* Left: Brand & Nav Links */}
        <div className="flex items-center gap-6 h-full">
          <Link to="/projects" className="flex items-center gap-2 group">
            <div className="w-6 h-6 bg-[#4b9fd5] flex items-center justify-center font-bold text-xs text-white rounded">
              Y
            </div>
            <span className="font-semibold tracking-tight uppercase text-sm text-white">
              yunq
            </span>
            <span className="text-[10px] text-[#4b9fd5] font-bold uppercase tracking-wider hidden sm:inline">
              Enterprise
            </span>
          </Link>

          {/* Navigation Links — role-gated */}
          <nav className="hidden md:flex items-center h-full gap-1 text-xs font-medium">
            {navItems.map((item) => {
              // Common: every authed user can see Overview/Projects/Issues/Rules.
              const inner = (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) =>
                    cn(
                      'h-full flex items-center px-3 transition-all relative font-medium',
                      isActive
                        ? 'border-b-2 border-[#4b9fd5] text-white font-bold opacity-100'
                        : 'text-white/80 hover:text-white hover:opacity-100'
                    )
                  }
                >
                  {item.label}
                </NavLink>
              );
              return 'permission' in item ? (
                <PermissionGate key={item.path} permission={item.permission}>
                  {inner}
                </PermissionGate>
              ) : (
                inner
              );
            })}
            {/* Quality Profiles / Quality Gates — only for users with the manage permission. */}
            {canManageProfiles && (
              <NavLink
                key="/quality_profiles"
                to="/quality_profiles"
                className={({ isActive }) =>
                  cn(
                    'h-full flex items-center px-3 transition-all relative font-medium',
                    isActive
                      ? 'border-b-2 border-[#4b9fd5] text-white font-bold opacity-100'
                      : 'text-white/80 hover:text-white hover:opacity-100'
                  )
                }
              >
                Quality Profiles
              </NavLink>
            )}
            {canManageQualityGates && (
              <NavLink
                key="/quality_gates"
                to="/quality_gates"
                className={({ isActive }) =>
                  cn(
                    'h-full flex items-center px-3 transition-all relative font-medium',
                    isActive
                      ? 'border-b-2 border-[#4b9fd5] text-white font-bold opacity-100'
                      : 'text-white/80 hover:text-white hover:opacity-100'
                  )
                }
              >
                Quality Gates
              </NavLink>
            )}
          </nav>
        </div>

        {/* Right: Search, Help, Notifications, User */}
        <div className="flex items-center gap-3 text-xs">
          {/* Quick Search trigger */}
          <button
            onClick={() => setSearchOpen(true)}
            className="flex items-center gap-2 bg-[#3b4b5b] hover:bg-[#435567] text-gray-200 hover:text-white px-3 py-1.5 rounded text-xs transition-all outline-none"
          >
            <Search className="w-3.5 h-3.5 text-gray-300" />
            <span className="hidden sm:inline">Search (cmd+k)</span>
          </button>

          {/* Help & Documentation */}
          <a
            href="https://github.com/pmaojo/yunq#readme"
            target="_blank"
            rel="noreferrer"
            className="p-1.5 text-gray-300 hover:text-white hover:bg-[#3b4b5b] rounded transition-colors"
            title="yunq Documentation"
          >
            <HelpCircle className="w-4 h-4" />
          </a>

          {/* Auth section: sign-in button or user profile */}
          {!isAuthenticated ? (
            <Link
              to="/login"
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#4b9fd5] hover:bg-[#3b8dc0] text-white rounded text-xs font-semibold transition-all"
            >
              <User className="w-3.5 h-3.5" />
              <span>Sign in</span>
            </Link>
          ) : (
            <div className="relative">
              <button
                onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                className="flex items-center gap-2 pl-2 pr-1 py-1 rounded hover:bg-[#3b4b5b] transition-colors"
              >
                <img
                  src={user?.avatar_url ?? 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80'}
                  alt={user?.name ?? 'User'}
                  className="w-6 h-6 rounded-full object-cover border border-white/20"
                />
                <span className="hidden lg:inline text-xs font-semibold text-slate-200">{user?.name ?? user?.username}</span>
                <ChevronDown className="w-3.5 h-3.5 text-gray-300" />
              </button>

              {/* Profile Dropdown */}
              {userDropdownOpen && (
                <div
                  className="absolute right-0 mt-2 w-56 bg-white rounded-md shadow-xl border border-gray-200 text-slate-800 py-2 z-50 animate-in fade-in zoom-in-95 duration-100"
                  onMouseLeave={() => setUserDropdownOpen(false)}
                >
                  <div className="px-4 py-2 border-b border-gray-100">
                    <p className="text-sm font-bold text-[#233445]">{user?.name ?? user?.username}</p>
                    <p className="text-xs text-gray-500 truncate">{user?.email ?? user?.username}</p>
                    {Array.isArray((user as any)?.roles) && (user as any).roles.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {(user as any).roles.map((role: string) => (
                          <span
                            key={role}
                            className="inline-block text-[10px] font-semibold text-[#4b9fd5] bg-sky-50 px-2 py-0.5 rounded border border-sky-200 capitalize"
                          >
                            {role}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                  <div className="py-1">
                    <Link
                      to="/admin"
                      onClick={() => setUserDropdownOpen(false)}
                      className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    >
                      <User className="w-3.5 h-3.5 text-slate-400" />
                      My Account & Security
                    </Link>
                    <button
                      onClick={handleLogout}
                      className="flex items-center gap-2 w-full text-left px-4 py-2 text-xs font-medium text-red-600 hover:bg-red-50 transition-colors"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      Sign out
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
