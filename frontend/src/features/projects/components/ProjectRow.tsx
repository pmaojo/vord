import React from 'react';
import { Link } from 'react-router-dom';
import { Project } from '../../../types';
import { QualityGateBadge } from '../../../components/common/QualityGateBadge';
import { RatingBadge } from '../../../components/common/RatingBadge';
import { formatTimeAgo, formatDuration, formatNumber } from '../../../lib/utils';
import { Calendar } from 'lucide-react';

interface ProjectRowProps {
  project: Project;
}

export const ProjectRow: React.FC<ProjectRowProps> = ({ project }) => {
  const encodedKey = encodeURIComponent(project.key);

  return (
    <tr className="hover:bg-[#f3f6f9] transition-colors border-b border-gray-200 text-xs">
      {/* Name & Key */}
      <td className="py-3 px-4 font-medium">
        <Link
          to={`/projects/${encodedKey}/overview`}
          className="font-semibold text-[#4b9fd5] hover:underline text-sm"
        >
          {project.name}
        </Link>
        <div className="flex items-center gap-2 text-[10px] font-mono text-gray-400 mt-0.5">
          <span>{project.key}</span>
          <span>•</span>
          <span className="text-gray-500 font-sans">{project.language}</span>
        </div>
      </td>

      {/* Quality Gate */}
      <td className="py-3.5 px-4 text-center">
        <QualityGateBadge status={project.qualityGateStatus} size="sm" />
      </td>

      {/* Reliability / Bugs */}
      <td className="py-3.5 px-4 text-center">
        <div className="flex items-center justify-center gap-2">
          <span className="font-bold text-slate-800">{formatNumber(project.metrics.bugs)}</span>
          <RatingBadge rating={project.metrics.bugsRating} size="sm" />
        </div>
      </td>

      {/* Security / Vulnerabilities */}
      <td className="py-3.5 px-4 text-center">
        <div className="flex items-center justify-center gap-2">
          <span className="font-bold text-slate-800">{formatNumber(project.metrics.vulnerabilities)}</span>
          <RatingBadge rating={project.metrics.vulnerabilitiesRating} size="sm" />
        </div>
      </td>

      {/* Maintainability / Debt */}
      <td className="py-3.5 px-4 text-center">
        <div className="flex items-center justify-center gap-2">
          <div className="text-right">
            <div className="font-bold text-slate-800">{formatNumber(project.metrics.codeSmells)}</div>
            <div className="text-[10px] text-slate-500 font-mono">
              {formatDuration(project.metrics.debtMinutes)}
            </div>
          </div>
          <RatingBadge rating={project.metrics.codeSmellsRating} size="sm" />
        </div>
      </td>

      {/* Coverage */}
      <td className="py-3.5 px-4 text-center font-bold">
        <span
          className={project.metrics.coverage >= 80 ? 'text-emerald-600' : 'text-rose-600'}
        >
          {project.metrics.coverage.toFixed(1)}%
        </span>
      </td>

      {/* Duplications */}
      <td className="py-3.5 px-4 text-center font-bold text-slate-700">
        {project.metrics.duplications.toFixed(1)}%
      </td>

      {/* LOC */}
      <td className="py-3.5 px-4 text-center font-mono text-xs text-slate-600">
        {formatNumber(project.metrics.ncloc)}
      </td>

      {/* Last Analyzed */}
      <td className="py-3.5 px-4 text-right text-xs text-slate-500 whitespace-nowrap">
        <div className="flex items-center justify-end gap-1 font-mono">
          <Calendar className="w-3 h-3 text-slate-400" />
          {formatTimeAgo(project.lastAnalysisDate)}
        </div>
      </td>
    </tr>
  );
};
