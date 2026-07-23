import React, { useState } from 'react';
import { NavLink, useParams } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { Project } from '../../types';
import { QualityGateBadge } from '../common/QualityGateBadge';
import { GitBranch, FolderGit2, Calendar, Settings, X, Plus, Trash2, Loader2 } from 'lucide-react';
import { formatTimeAgo, cn } from '../../lib/utils';
import { grantPermission, revokePermission } from '../../lib/api';
import { useAuditLog } from '../../lib/queries';

interface ProjectHeaderProps {
  project: Project;
  currentBranch: string;
  onBranchChange: (branch: string) => void;
}

export const ProjectHeader: React.FC<ProjectHeaderProps> = ({
  project,
  currentBranch,
  onBranchChange,
}) => {
  const { projectKey } = useParams<{ projectKey: string }>();
  const encodedKey = encodeURIComponent(project.key);
  const [settingsOpen, setSettingsOpen] = useState(false);

  const subNavs = [
    { label: 'Overview', path: `/projects/${encodedKey}/overview` },
    { label: 'Issues', path: `/projects/${encodedKey}/issues` },
    { label: 'Measures', path: `/projects/${encodedKey}/measures` },
    { label: 'Code', path: `/projects/${encodedKey}/code` },
    { label: 'Activity', path: `/projects/${encodedKey}/activity` },
  ];

  return (
    <div className="bg-white border-b border-slate-200 shadow-xs select-none">
      <div className="max-w-7xl mx-auto px-4 pt-4 pb-0">
        {/* Top Info Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-100 rounded-lg text-slate-600">
              <FolderGit2 className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold text-slate-900 tracking-tight">{project.name}</h1>
                <span className="text-xs font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                  {project.key}
                </span>
                <span className="text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded bg-slate-200 text-slate-700">
                  {project.visibility}
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5 flex items-center gap-2">
                <span>{project.description}</span>
                <span>•</span>
                <span className="flex items-center gap-1 font-mono">
                  <Calendar className="w-3 h-3 text-slate-400" />
                  Analyzed {formatTimeAgo(project.lastAnalysisDate)}
                </span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Branch Switcher */}
            <div className="flex items-center gap-1.5 bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1 text-xs font-semibold text-slate-700">
              <GitBranch className="w-3.5 h-3.5 text-slate-500" />
              <select
                value={currentBranch}
                onChange={(e) => onBranchChange(e.target.value)}
                className="bg-transparent border-none outline-none font-medium cursor-pointer"
              >
                {project.branches.map((b) => (
                  <option key={b.name} value={b.name}>
                    {b.name} {b.isMain ? '(main)' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* Quality Gate Status */}
            <QualityGateBadge status={project.qualityGateStatus} size="lg" />

            {/* Settings button */}
            <button
              onClick={() => setSettingsOpen(true)}
              className="p-2 text-slate-500 hover:text-slate-800 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors"
              title="Project Permissions"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Sub Navigation Tabs */}
        <div className="flex space-x-6 border-t border-slate-100">
          {subNavs.map((nav) => (
            <NavLink
              key={nav.path}
              to={nav.path}
              className={({ isActive }) =>
                cn(
                  'py-3 text-xs font-bold transition-colors border-b-2 relative -mb-px uppercase tracking-wider',
                  isActive
                    ? 'border-[#4b9fd5] text-[#4b9fd5]'
                    : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
                )
              }
            >
              {nav.label}
            </NavLink>
          ))}
        </div>
      </div>

      {settingsOpen && <ProjectPermissionsModal projectKey={project.key} onClose={() => setSettingsOpen(false)} />}
    </div>
  );
};

const ProjectPermissionsModal: React.FC<{ projectKey: string; onClose: () => void }> = ({ projectKey, onClose }) => {
  const queryClient = useQueryClient();
  const { data: auditLog, isLoading } = useAuditLog('project_permission');
  const [userLogin, setUserLogin] = useState('');
  const [role, setRole] = useState('viewer');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const grants = (auditLog?.items ?? []).filter((entry) => entry.entity_id.startsWith(`${projectKey}:`));

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!userLogin) return;
    setSaving(true);
    setError(null);
    try {
      await grantPermission(projectKey, userLogin, role);
      setUserLogin('');
      queryClient.invalidateQueries({ queryKey: ['audit-log', 'project_permission'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to grant permission');
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (user: string) => {
    try {
      await revokePermission(projectKey, user);
      queryClient.invalidateQueries({ queryKey: ['audit-log', 'project_permission'] });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to revoke permission');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4">
      <div className="bg-white rounded-2xl shadow-2xl border border-slate-200 max-w-md w-full p-6 animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3 mb-4">
          <h3 className="text-lg font-bold text-slate-900">Project Permissions</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600">
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs text-slate-500 mb-4 font-mono">{projectKey}</p>

        <form onSubmit={handleGrant} className="flex items-end gap-2 mb-4">
          <div className="flex-1">
            <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">User Login</label>
            <input
              type="text"
              value={userLogin}
              onChange={(e) => setUserLogin(e.target.value)}
              placeholder="octocat"
              className="w-full bg-slate-50 border border-slate-300 rounded px-2.5 py-1.5 text-xs font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold text-slate-500 uppercase mb-1">Role</label>
            <select
              value={role}
              onChange={(e) => setRole(e.target.value)}
              className="bg-slate-50 border border-slate-300 rounded px-2.5 py-1.5 text-xs font-bold"
            >
              <option value="admin">admin</option>
              <option value="editor">editor</option>
              <option value="viewer">viewer</option>
            </select>
          </div>
          <button
            type="submit"
            disabled={saving}
            className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white font-bold text-xs rounded flex items-center gap-1.5"
          >
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
          </button>
        </form>

        {error && (
          <div className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded px-2.5 py-1.5 mb-3">
            {error}
          </div>
        )}

        <div className="space-y-1 text-xs font-mono max-h-48 overflow-y-auto">
          {isLoading && <div className="text-slate-400">Loading...</div>}
          {!isLoading && grants.length === 0 && <div className="text-slate-400">No grants recorded yet.</div>}
          {grants.map((entry) => {
            const user = entry.entity_id.split(':')[1];
            const afterRole =
              entry.after && typeof entry.after === 'object' && 'role' in (entry.after as Record<string, unknown>)
                ? String((entry.after as Record<string, unknown>).role)
                : null;
            return (
              <div key={entry.id} className="flex items-center justify-between border-b border-slate-100 py-1.5">
                <span>{user} {afterRole ? `(${afterRole})` : '(revoked)'}</span>
                {afterRole && (
                  <button onClick={() => handleRevoke(user)} className="text-rose-500 hover:text-rose-700">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
