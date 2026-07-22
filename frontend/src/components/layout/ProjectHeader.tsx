import React from 'react';
import { NavLink, useParams } from 'react-router-dom';
import { Project } from '../../types';
import { QualityGateBadge } from '../common/QualityGateBadge';
import { GitBranch, FolderGit2, Calendar, Settings } from 'lucide-react';
import { formatTimeAgo, cn } from '../../lib/utils';

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
              onClick={() => alert(`Project settings for ${project.name}`)}
              className="p-2 text-slate-500 hover:text-slate-800 hover:bg-slate-100 rounded-lg border border-slate-200 transition-colors"
              title="Project Settings"
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
    </div>
  );
};
