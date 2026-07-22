import React, { useState } from 'react';
import { NavLink, Link } from 'react-router-dom';
import { useGlobalStore } from '../../stores/global-store';
import {
  Search,
  HelpCircle,
  Bell,
  ShieldCheck,
  User,
  LogOut,
  ChevronDown,
  Sparkles
} from 'lucide-react';
import { cn } from '../../lib/utils';

export const TopNavbar: React.FC = () => {
  const { setSearchOpen, user } = useGlobalStore();
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);

  const navItems = [
    { label: 'Overview', path: '/landing' },
    { label: 'Projects', path: '/projects' },
    { label: 'Issues', path: '/issues' },
    { label: 'Rules', path: '/rules' },
    { label: 'Quality Profiles', path: '/quality_profiles' },
    { label: 'Quality Gates', path: '/quality_gates' },
    { label: 'Administration', path: '/admin' },
  ];

  return (
    <header className="bg-[#233445] text-white border-b border-[#1c2a38] sticky top-0 z-40 shadow-xs select-none h-12 flex items-center">
      <div className="max-w-7xl mx-auto px-4 w-full h-full flex items-center justify-between">
        {/* Left: Brand & Nav Links */}
        <div className="flex items-center gap-6 h-full">
          <Link to="/projects" className="flex items-center gap-2 group">
            <div className="w-6 h-6 bg-[#4b9fd5] flex items-center justify-center font-bold text-xs text-white rounded">
              S
            </div>
            <span className="font-semibold tracking-tight uppercase text-sm text-white">
              SonarQube
            </span>
            <span className="text-[10px] text-[#4b9fd5] font-bold uppercase tracking-wider hidden sm:inline">
              Enterprise
            </span>
          </Link>

          {/* Navigation Links */}
          <nav className="hidden md:flex items-center h-full gap-1 text-xs font-medium">
            {navItems.map((item) => (
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
            ))}
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
            href="https://docs.sonarsource.com/sonarqube/latest/"
            target="_blank"
            rel="noreferrer"
            className="p-1.5 text-gray-300 hover:text-white hover:bg-[#3b4b5b] rounded transition-colors"
            title="SonarQube Documentation"
          >
            <HelpCircle className="w-4 h-4" />
          </a>

          {/* Notifications */}
          <button
            className="p-1.5 text-gray-300 hover:text-white hover:bg-[#3b4b5b] rounded transition-colors relative"
            title="Notifications"
          >
            <Bell className="w-4 h-4" />
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-[#4b9fd5] ring-2 ring-[#233445]"></span>
          </button>

          {/* User Profile */}
          <div className="relative">
            <button
              onClick={() => setUserDropdownOpen(!userDropdownOpen)}
              className="flex items-center gap-2 pl-2 pr-1 py-1 rounded hover:bg-[#3b4b5b] transition-colors"
            >
              <img
                src={user.avatar}
                alt={user.name}
                className="w-6 h-6 rounded-full object-cover border border-white/20"
              />
              <span className="hidden lg:inline text-xs font-semibold text-slate-200">{user.name}</span>
              <ChevronDown className="w-3.5 h-3.5 text-gray-300" />
            </button>

            {/* Profile Dropdown */}
            {userDropdownOpen && (
              <div
                className="absolute right-0 mt-2 w-56 bg-white rounded-md shadow-xl border border-gray-200 text-slate-800 py-2 z-50 animate-in fade-in zoom-in-95 duration-100"
                onMouseLeave={() => setUserDropdownOpen(false)}
              >
                <div className="px-4 py-2 border-b border-gray-100">
                  <p className="text-sm font-bold text-[#233445]">{user.name}</p>
                  <p className="text-xs text-gray-500 truncate">{user.email}</p>
                  <span className="inline-block mt-1 text-[10px] font-semibold text-[#4b9fd5] bg-sky-50 px-2 py-0.5 rounded border border-sky-200">
                    {user.role}
                  </span>
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
                  <a
                    href="#"
                    onClick={(e) => {
                      e.preventDefault();
                      setUserDropdownOpen(false);
                      alert('You are logged in as System Administrator.');
                    }}
                    className="flex items-center gap-2 px-4 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-[#4b9fd5]" />
                    License & Features
                  </a>
                </div>
                <div className="border-t border-gray-100 pt-1">
                  <button
                    onClick={() => {
                      setUserDropdownOpen(false);
                      alert('SonarQube Session: You are using local administrator privileges.');
                    }}
                    className="w-full text-left flex items-center gap-2 px-4 py-2 text-xs font-medium text-rose-600 hover:bg-rose-50"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Log out
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
