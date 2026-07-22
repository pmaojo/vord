import React from 'react';
import { Link } from 'react-router-dom';
import { Project } from '../../../types';
import { QualityGateBadge } from '../../../components/common/QualityGateBadge';
import { RatingBadge } from '../../../components/common/RatingBadge';
import { formatTimeAgo, formatDuration, formatNumber } from '../../../lib/utils';
import { Bug, ShieldCheck, Wrench, Flame, PieChart, Copy, GitBranch, Calendar } from 'lucide-react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip } from 'recharts';

interface ProjectCardProps {
  project: Project;
}

export const ProjectCard: React.FC<ProjectCardProps> = ({ project }) => {
  const encodedKey = encodeURIComponent(project.key);
  const mainBranch = project.branches.find((b) => b.isMain)?.name || 'main';

  return (
    <div className="bg-white rounded border border-gray-200 hover:border-[#4b9fd5] transition-colors shadow-2xs flex flex-col justify-between group">
      {/* Card Header */}
      <div className="p-4 border-b border-gray-100">
        <div className="flex items-start justify-between gap-3">
          <div>
            <Link
              to={`/projects/${encodedKey}/overview`}
              className="text-sm font-semibold text-[#4b9fd5] hover:underline tracking-tight line-clamp-1"
            >
              {project.name}
            </Link>
            <p className="text-[10px] text-gray-400 font-mono mt-0.5">{project.key}</p>
          </div>
          <QualityGateBadge status={project.qualityGateStatus} size="sm" />
        </div>

        {/* Tags & Language */}
        <div className="flex flex-wrap items-center gap-1.5 mt-2.5">
          <span className="bg-gray-100 px-2 py-0.5 rounded text-[10px] font-medium text-gray-600">
            {project.language}
          </span>
          {project.tags.map((tag) => (
            <span
              key={tag}
              className="bg-gray-50 px-2 py-0.5 rounded text-[10px] text-gray-500 border border-gray-200"
            >
              #{tag}
            </span>
          ))}
        </div>
      </div>

      {/* Metrics Grid (2x3 or 3x2) */}
      <div className="p-5 grid grid-cols-2 gap-4 bg-slate-50/50">
        {/* Reliability & Bugs */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/60 shadow-2xs">
          <div className="flex items-center gap-2">
            <Bug className="w-4 h-4 text-red-500 shrink-0" />
            <div>
              <div className="text-sm font-bold text-slate-900">{formatNumber(project.metrics.bugs)}</div>
              <div className="text-[10px] font-medium text-slate-500 uppercase tracking-wider">Bugs</div>
            </div>
          </div>
          <RatingBadge rating={project.metrics.bugsRating} size="sm" />
        </div>

        {/* Security & Vulnerabilities */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/60 shadow-2xs">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-rose-500 shrink-0" />
            <div>
              <div className="text-sm font-bold text-slate-900">{formatNumber(project.metrics.vulnerabilities)}</div>
              <div className="text-[10px] font-medium text-slate-500 uppercase tracking-wider">Vulnerabilities</div>
            </div>
          </div>
          <RatingBadge rating={project.metrics.vulnerabilitiesRating} size="sm" />
        </div>

        {/* Maintainability & Debt */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/60 shadow-2xs">
          <div className="flex items-center gap-2">
            <Wrench className="w-4 h-4 text-amber-500 shrink-0" />
            <div>
              <div className="text-sm font-bold text-slate-900">{formatNumber(project.metrics.codeSmells)}</div>
              <div className="text-[10px] font-medium text-slate-500">
                Debt {formatDuration(project.metrics.debtMinutes)}
              </div>
            </div>
          </div>
          <RatingBadge rating={project.metrics.codeSmellsRating} size="sm" />
        </div>

        {/* Coverage */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/60 shadow-2xs">
          <div className="flex items-center gap-2">
            <PieChart className="w-4 h-4 text-emerald-500 shrink-0" />
            <div>
              <div className="text-sm font-bold text-slate-900">{project.metrics.coverage.toFixed(1)}%</div>
              <div className="text-[10px] font-medium text-slate-500 uppercase tracking-wider">Coverage</div>
            </div>
          </div>
          <div className="w-8 bg-slate-100 rounded-full h-1.5 overflow-hidden border border-slate-200">
            <div
              className={`h-full ${project.metrics.coverage >= 80 ? 'bg-emerald-500' : 'bg-rose-500'}`}
              style={{ width: `${project.metrics.coverage}%` }}
            ></div>
          </div>
        </div>

        {/* Security Hotspots */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/60 shadow-2xs">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-500 shrink-0" />
            <div>
              <div className="text-sm font-bold text-slate-900">{project.metrics.securityHotspots}</div>
              <div className="text-[10px] font-medium text-slate-500">
                {project.metrics.securityHotspotsReviewed}% Rev.
              </div>
            </div>
          </div>
        </div>

        {/* Duplications & LOC */}
        <div className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200/60 shadow-2xs">
          <div className="flex items-center gap-2">
            <Copy className="w-4 h-4 text-indigo-500 shrink-0" />
            <div>
              <div className="text-sm font-bold text-slate-900">{project.metrics.duplications.toFixed(1)}%</div>
              <div className="text-[10px] font-medium text-slate-500">{formatNumber(project.metrics.ncloc)} LOC</div>
            </div>
          </div>
        </div>
      </div>

      {/* Sparkline Trend Chart */}
      <div className="px-5 py-3 border-t border-slate-100 bg-white">
        <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
          30-Day Quality Trend
        </div>
        <div className="h-12 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={project.sparkline} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id={`grad-${project.key}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#0284c7" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#0284c7" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="date" hide />
              <YAxis hide domain={['dataMin - 1', 'dataMax + 1']} />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-slate-900 text-white text-[10px] px-2 py-1 rounded shadow-md font-mono">
                        <div>{data.date}</div>
                        <div>Coverage: {data.coverage}%</div>
                        <div>Smells: {data.codeSmells}</div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Area
                type="monotone"
                dataKey="coverage"
                stroke="#0284c7"
                strokeWidth={2}
                fillOpacity={1}
                fill={`url(#grad-${project.key})`}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Footer */}
      <div className="px-5 py-2.5 bg-slate-50 border-t border-slate-200 text-xs text-slate-500 flex items-center justify-between">
        <span className="flex items-center gap-1 font-mono">
          <GitBranch className="w-3 h-3 text-slate-400" />
          {mainBranch}
        </span>
        <span className="flex items-center gap-1 text-[11px]">
          <Calendar className="w-3 h-3 text-slate-400" />
          {formatTimeAgo(project.lastAnalysisDate)}
        </span>
      </div>
    </div>
  );
};
