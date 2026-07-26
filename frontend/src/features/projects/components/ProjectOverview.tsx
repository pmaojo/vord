import React, { useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { MOCK_PROJECTS } from '../../../testing/mock-data';
import type { Project } from '../../../types';
import { ProjectHeader } from '../../../components/layout/ProjectHeader';
import { RatingBadge } from '../../../components/common/RatingBadge';
import { QualityGateBadge } from '../../../components/common/QualityGateBadge';
import { useProjectActivity } from '../../../lib/queries';
import { formatDuration, formatNumber } from '../../../lib/utils';
import {
  AlertTriangle,
  CheckCircle2,
  Bug,
  ShieldCheck,
  Wrench,
  PieChart,
  Copy,
  Flame,
  ArrowUpRight,
  TrendingUp,
  Activity,
  XCircle,
  PlayCircle,
  Loader2,
} from 'lucide-react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid, Legend } from 'recharts';

export const ProjectOverview: React.FC = () => {
  const { projectKey } = useParams<{ projectKey: string }>();
  const navigate = useNavigate();

  const decodedKey = projectKey ? decodeURIComponent(projectKey) : '';
  const project: Project | undefined = MOCK_PROJECTS.find((p) => p.key === decodedKey) ?? MOCK_PROJECTS[0];

  const [currentBranch, setCurrentBranch] = useState(
    project?.branches.find((b) => b.isMain)?.name || 'main'
  );

  const [activeTabCodeScope, setActiveTabCodeScope] = useState<'NEW_CODE' | 'OVERALL'>('NEW_CODE');
  const [timelineMetric, setTimelineMetric] = useState<'coverage' | 'codeSmells' | 'bugs'>('coverage');

  // MOCK_PROJECTS is currently empty (this page has no real project-metrics
  // data source wired in yet) — render a clear placeholder for the mocked
  // metrics instead of crashing on `undefined.branches` above, but still
  // show the real activity feed below since that doesn't depend on the mock
  // project object at all.
  if (!project) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-16 space-y-8">
        <div className="text-center text-sm text-slate-500">
          No project metrics available for <span className="font-mono font-bold">{decodedKey || 'this key'}</span>.
          Project overview metrics still read from local mock data, which is currently empty.
        </div>
        <RecentActivityPanel projectKey={decodedKey} />
      </div>
    );
  }

  const encodedKey = encodeURIComponent(project.key);

  return (
    <div>
      {/* Project Header Navigation */}
      <ProjectHeader
        project={project}
        currentBranch={currentBranch}
        onBranchChange={setCurrentBranch}
      />

      <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
        {/* Quality Gate Detailed Status Banner */}
        <div
          className={`rounded-2xl p-6 border shadow-xs transition-all ${
            project.qualityGateStatus === 'PASSED'
              ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
              : 'bg-rose-50/70 border-rose-200 text-rose-950'
          }`}
        >
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-4">
              <div
                className={`p-3 rounded-xl ${
                  project.qualityGateStatus === 'PASSED' ? 'bg-emerald-500 text-white' : 'bg-rose-600 text-white'
                }`}
              >
                {project.qualityGateStatus === 'PASSED' ? (
                  <CheckCircle2 className="w-8 h-8" />
                ) : (
                  <AlertTriangle className="w-8 h-8" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-black tracking-tight">
                    Quality Gate {project.qualityGateStatus === 'PASSED' ? 'Passed' : 'Failed'}
                  </h2>
                  <QualityGateBadge status={project.qualityGateStatus} size="sm" />
                </div>
                <p className="text-xs font-medium opacity-80 mt-1">
                  Conditions enforced on branch <span className="font-mono font-bold">{currentBranch}</span>
                </p>

                {/* Failing conditions list */}
                {project.qualityGateStatus === 'FAILED' && project.failedGateConditions && (
                  <div className="mt-4 bg-white/80 backdrop-blur-xs rounded-xl p-4 border border-rose-200 shadow-xs">
                    <div className="text-xs font-bold text-rose-900 uppercase tracking-wider mb-2">
                      Failed Conditions ({project.failedGateConditions.length}):
                    </div>
                    <ul className="space-y-1.5 text-xs text-rose-800 font-medium">
                      {project.failedGateConditions.map((cond, idx) => (
                        <li key={idx} className="flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-600"></span>
                          <span>{cond}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            <button
              onClick={() => navigate(`/projects/${encodedKey}/issues`)}
              className="px-4 py-2 bg-white text-slate-800 font-bold text-xs rounded-xl border border-slate-300 hover:bg-slate-50 transition-colors shadow-2xs flex items-center gap-1.5"
            >
              <span>View Open Issues ({project.metrics.bugs + project.metrics.codeSmells + project.metrics.vulnerabilities})</span>
              <ArrowUpRight className="w-4 h-4 text-slate-500" />
            </button>
          </div>
        </div>

        {/* Code Scope Tabs (New Code vs Overall Code) */}
        <div className="flex items-center justify-between border-b border-slate-200 pb-2">
          <div className="flex space-x-2 bg-slate-100 p-1 rounded-xl">
            <button
              onClick={() => setActiveTabCodeScope('NEW_CODE')}
              className={`px-4 py-1.5 text-xs font-bold rounded-lg transition-all ${
                activeTabCodeScope === 'NEW_CODE'
                  ? 'bg-white text-sky-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              New Code (Since Last Release)
            </button>
            <button
              onClick={() => setActiveTabCodeScope('OVERALL')}
              className={`px-4 py-1.5 text-xs font-bold rounded-lg transition-all ${
                activeTabCodeScope === 'OVERALL'
                  ? 'bg-white text-sky-700 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Overall Codebase
            </button>
          </div>

          <div className="text-xs text-slate-500 font-mono">
            Total Lines of Code: <b>{formatNumber(project.metrics.ncloc)}</b>
          </div>
        </div>

        {/* Main Metric Cards Grid (5 core pillars) */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
          {/* 1. Reliability */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Reliability</span>
                <RatingBadge rating={project.metrics.bugsRating} size="md" />
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900">
                  {activeTabCodeScope === 'NEW_CODE'
                    ? project.metrics.newBugs ?? 0
                    : project.metrics.bugs}
                </span>
                <span className="text-xs font-medium text-slate-500">Bugs</span>
              </div>
            </div>
            <button
              onClick={() => navigate(`/projects/${encodedKey}/issues?type=BUG`)}
              className="mt-6 text-xs text-sky-600 hover:text-sky-800 font-bold flex items-center justify-between pt-3 border-t border-slate-100"
            >
              <span>Explore Bugs</span>
              <Bug className="w-4 h-4 text-red-500" />
            </button>
          </div>

          {/* 2. Security */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Security</span>
                <RatingBadge rating={project.metrics.vulnerabilitiesRating} size="md" />
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900">
                  {activeTabCodeScope === 'NEW_CODE'
                    ? project.metrics.newVulnerabilities ?? 0
                    : project.metrics.vulnerabilities}
                </span>
                <span className="text-xs font-medium text-slate-500">Vulnerabilities</span>
              </div>
            </div>
            <button
              onClick={() => navigate(`/projects/${encodedKey}/issues?type=VULNERABILITY`)}
              className="mt-6 text-xs text-sky-600 hover:text-sky-800 font-bold flex items-center justify-between pt-3 border-t border-slate-100"
            >
              <span>Explore Security</span>
              <ShieldCheck className="w-4 h-4 text-rose-500" />
            </button>
          </div>

          {/* 3. Maintainability */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Maintainability</span>
                <RatingBadge rating={project.metrics.codeSmellsRating} size="md" />
              </div>
              <div className="mt-4 flex items-baseline gap-2">
                <span className="text-3xl font-black text-slate-900">
                  {activeTabCodeScope === 'NEW_CODE'
                    ? project.metrics.newCodeSmells ?? 0
                    : project.metrics.codeSmells}
                </span>
                <span className="text-xs font-medium text-slate-500">Code Smells</span>
              </div>
              <div className="text-xs text-slate-500 font-mono mt-1">
                Debt: {formatDuration(project.metrics.debtMinutes)}
              </div>
            </div>
            <button
              onClick={() => navigate(`/projects/${encodedKey}/issues?type=CODE_SMELL`)}
              className="mt-6 text-xs text-sky-600 hover:text-sky-800 font-bold flex items-center justify-between pt-3 border-t border-slate-100"
            >
              <span>Explore Smells</span>
              <Wrench className="w-4 h-4 text-amber-500" />
            </button>
          </div>

          {/* 4. Coverage */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Coverage</span>
                <PieChart className="w-5 h-5 text-emerald-500" />
              </div>
              <div className="mt-4 flex items-baseline gap-1">
                <span className="text-3xl font-black text-slate-900">
                  {activeTabCodeScope === 'NEW_CODE'
                    ? (project.metrics.newCoverage ?? project.metrics.coverage).toFixed(1)
                    : project.metrics.coverage.toFixed(1)}
                  %
                </span>
              </div>
              <div className="text-xs text-slate-500 font-mono mt-1">
                Uncovered: {project.metrics.uncoveredLines} lines
              </div>
            </div>
            <button
              onClick={() => navigate(`/projects/${encodedKey}/measures?metric=coverage`)}
              className="mt-6 text-xs text-sky-600 hover:text-sky-800 font-bold flex items-center justify-between pt-3 border-t border-slate-100"
            >
              <span>View Coverage</span>
              <TrendingUp className="w-4 h-4 text-emerald-500" />
            </button>
          </div>

          {/* 5. Duplications */}
          <div className="bg-white rounded-2xl border border-slate-200 p-5 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Duplications</span>
                <Copy className="w-5 h-5 text-indigo-500" />
              </div>
              <div className="mt-4 flex items-baseline gap-1">
                <span className="text-3xl font-black text-slate-900">
                  {activeTabCodeScope === 'NEW_CODE'
                    ? (project.metrics.newDuplications ?? project.metrics.duplications).toFixed(1)
                    : project.metrics.duplications.toFixed(1)}
                  %
                </span>
              </div>
              <div className="text-xs text-slate-500 font-mono mt-1">
                Blocks: {project.metrics.duplicatedBlocks}
              </div>
            </div>
            <button
              onClick={() => navigate(`/projects/${encodedKey}/measures?metric=duplications`)}
              className="mt-6 text-xs text-sky-600 hover:text-sky-800 font-bold flex items-center justify-between pt-3 border-t border-slate-100"
            >
              <span>View Duplications</span>
              <Flame className="w-4 h-4 text-indigo-500" />
            </button>
          </div>
        </div>

        {/* Activity Timeline Chart Section */}
        <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
            <div className="flex items-center gap-2">
              <Activity className="w-5 h-5 text-sky-600" />
              <h3 className="text-lg font-bold text-slate-900">Activity Timeline & Metric Evolution</h3>
            </div>

            {/* Metric Toggle */}
            <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-lg text-xs font-bold">
              <button
                onClick={() => setTimelineMetric('coverage')}
                className={`px-3 py-1 rounded-md transition-colors ${
                  timelineMetric === 'coverage' ? 'bg-white text-sky-700 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Coverage %
              </button>
              <button
                onClick={() => setTimelineMetric('codeSmells')}
                className={`px-3 py-1 rounded-md transition-colors ${
                  timelineMetric === 'codeSmells' ? 'bg-white text-sky-700 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Code Smells
              </button>
              <button
                onClick={() => setTimelineMetric('bugs')}
                className={`px-3 py-1 rounded-md transition-colors ${
                  timelineMetric === 'bugs' ? 'bg-white text-sky-700 shadow-2xs' : 'text-slate-600'
                }`}
              >
                Bugs Count
              </button>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={project.sparkline} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="date" stroke="#94a3b8" fontSize={12} />
                <YAxis stroke="#94a3b8" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', color: '#fff', borderRadius: '8px' }}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey={timelineMetric}
                  name={
                    timelineMetric === 'coverage'
                      ? 'Coverage %'
                      : timelineMetric === 'codeSmells'
                      ? 'Code Smells'
                      : 'Bugs'
                  }
                  stroke="#0284c7"
                  strokeWidth={3}
                  dot={{ r: 5, fill: '#0284c7' }}
                  activeDot={{ r: 8 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <RecentActivityPanel projectKey={decodedKey} />
      </div>
    </div>
  );
};

/** Real data, `GET /api/projects/{key}/activity` — no mock dependency. */
const RecentActivityPanel: React.FC<{ projectKey: string }> = ({ projectKey }) => {
  const { data: activityLog, isLoading: activityLoading } = useProjectActivity(projectKey);

  return (
    <div className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs">
      <div className="flex items-center gap-2 mb-4">
        <Activity className="w-5 h-5 text-sky-600" />
        <h3 className="text-lg font-bold text-slate-900">Recent Activity</h3>
        <span className="text-xs text-slate-400 font-mono ml-auto">GET /api/projects/{'{key}'}/activity</span>
      </div>

      {activityLoading ? (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-8 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading activity...
        </div>
      ) : (activityLog?.items.length ?? 0) === 0 ? (
        <div className="text-xs text-slate-400 font-mono text-center py-8">
          No background task activity recorded yet for <b>{projectKey}</b> — run a scan to populate this feed.
        </div>
      ) : (
        <ul className="space-y-2">
          {activityLog!.items.map((entry) => {
            const isFailed = entry.event_type === 'scan.failed';
            const isSucceeded = entry.event_type === 'scan.succeeded';
            const Icon = isFailed ? XCircle : isSucceeded ? CheckCircle2 : PlayCircle;
            const iconClass = isFailed ? 'text-rose-500' : isSucceeded ? 'text-emerald-500' : 'text-sky-500';
            return (
              <li key={entry.id} className="flex items-start gap-3 text-xs border-b border-slate-100 last:border-0 py-2">
                <Icon className={`w-4 h-4 shrink-0 mt-0.5 ${iconClass}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-700 font-mono">{entry.event_type}</span>
                    <span className="text-slate-400 font-mono">{entry.at}</span>
                  </div>
                  <div className="text-slate-600 mt-0.5 truncate" title={entry.message}>
                    {entry.message}
                  </div>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
};
