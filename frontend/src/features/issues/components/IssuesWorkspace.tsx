import React, { useState, useMemo } from 'react';
import { useParams } from 'react-router-dom';
import { fetchIssuesFromApi, assignIssue, bulkTransitionIssues } from '../../../lib/api';
import { useIssuesStore } from '../stores/useIssuesStore';
import { useRules, useProjects } from '../../../lib/queries';
import { useQuery } from '@tanstack/react-query';
import { mapApiIssueToIssue } from '../mapIssue';
import { IssueItem } from './IssueItem';
import { IssueFilters } from './IssueFilters';
import { ProjectHeader } from '../../../components/layout/ProjectHeader';
import { Issue, Project } from '../../../types';
import { Search, UserCheck, CheckCircle, CheckSquare, Square, Loader2 } from 'lucide-react';
import { formatDuration } from '../../../lib/utils';

export const IssuesWorkspace: React.FC = () => {
  const { projectKey } = useParams<{ projectKey: string }>();
  const decodedProjectKey = projectKey ? decodeURIComponent(projectKey) : null;

  const { data: apiProjects } = useProjects();
  const apiProject = decodedProjectKey ? apiProjects?.find((p) => p.key === decodedProjectKey) : null;

  // ProjectHeader only reads name/key/visibility/description/lastAnalysisDate/
  // branches/qualityGateStatus — everything else the real /api/projects
  // response doesn't carry yet, so it's defaulted rather than fabricated.
  const project: Project | null = apiProject
    ? {
        key: apiProject.key,
        name: apiProject.name,
        description: '',
        qualityGateStatus: apiProject.quality_gate_status as Project['qualityGateStatus'],
        metrics: {} as Project['metrics'],
        lastAnalysisDate: apiProject.last_analysis_date,
        tags: [],
        language: '',
        branches: [{ name: 'main', isMain: true, status: apiProject.quality_gate_status as Project['qualityGateStatus'], lastAnalysis: apiProject.last_analysis_date }],
        sparkline: [],
        visibility: 'private',
      }
    : null;

  const [currentBranch, setCurrentBranch] = useState('main');

  const { data: rules } = useRules();
  const ruleIndex = useMemo(() => new Map((rules ?? []).map((r) => [r.id, r])), [rules]);

  const { data: issuePage, isLoading, refetch } = useQuery({
    queryKey: ['issues', 'workspace'],
    queryFn: () => fetchIssuesFromApi({ pageSize: 200 }),
  });

  const [localOverrides, setLocalOverrides] = useState<Record<string, Issue>>({});

  const issuesList: Issue[] = useMemo(() => {
    const key = decodedProjectKey || 'yunq-core-platform';
    return (issuePage?.items ?? []).map((item) => {
      const mapped = mapApiIssueToIssue(item, key, ruleIndex);
      return localOverrides[mapped.id] ?? mapped;
    });
  }, [issuePage, ruleIndex, decodedProjectKey, localOverrides]);

  const handleIssueUpdated = (updated: Issue) => {
    setLocalOverrides((prev) => ({ ...prev, [updated.id]: updated }));
  };

  const {
    searchQuery,
    setSearchQuery,
    selectedTypes,
    selectedSeverities,
    selectedStatuses,
    assigneeFilter,
    selectedIssueIds,
    toggleIssueSelection,
    selectAllIssues,
    clearIssueSelections,
  } = useIssuesStore();

  const availableAssignees = useMemo(
    () => Array.from(new Set(issuesList.map((i) => i.assignee).filter((a): a is string => !!a))).sort(),
    [issuesList]
  );

  const filteredIssues = issuesList.filter((issue) => {
    if (
      searchQuery &&
      !issue.message.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !issue.ruleKey.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !issue.component.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    if (selectedTypes.length > 0 && !selectedTypes.includes(issue.type)) return false;
    if (selectedSeverities.length > 0 && !selectedSeverities.includes(issue.severity)) return false;
    if (selectedStatuses.length > 0 && !selectedStatuses.includes(issue.status)) return false;
    if (assigneeFilter === 'UNASSIGNED' && issue.assignee) return false;
    if (assigneeFilter !== 'ALL' && assigneeFilter !== 'UNASSIGNED' && issue.assignee !== assigneeFilter) return false;
    return true;
  });

  const totalDebtMinutes = filteredIssues.reduce((sum, i) => sum + i.effortMinutes, 0);

  const [bulkPending, setBulkPending] = useState(false);

  const handleBulkAssignToMe = async () => {
    setBulkPending(true);
    try {
      await Promise.all(selectedIssueIds.map((id) => assignIssue(Number(id), 'Administrator')));
      await refetch();
      clearIssueSelections();
    } finally {
      setBulkPending(false);
    }
  };

  const handleBulkResolve = async (resolution: 'fixed' | 'wont-fix' | 'false-positive') => {
    setBulkPending(true);
    try {
      await bulkTransitionIssues(selectedIssueIds.map(Number), 'resolve', resolution);
      await refetch();
      clearIssueSelections();
    } finally {
      setBulkPending(false);
    }
  };

  const allFilteredIds = filteredIssues.map((i) => i.id);
  const isAllSelected = allFilteredIds.length > 0 && allFilteredIds.every((id) => selectedIssueIds.includes(id));

  return (
    <div>
      {project && (
        <ProjectHeader project={project} currentBranch={currentBranch} onBranchChange={setCurrentBranch} />
      )}

      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">
              {project ? `Issues in ${project.name}` : 'Global Issues Workspace'}
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              Showing {filteredIssues.length} issues matching current query criteria
            </p>
          </div>

          <div className="relative w-72 sm:w-96">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by rule, message, or file path..."
              className="w-full bg-white border border-slate-300 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-sky-500 shadow-2xs font-medium"
            />
          </div>
        </div>

        {selectedIssueIds.length > 0 && (
          <div className="mb-6 bg-slate-900 text-white rounded-xl p-3 px-5 flex flex-wrap items-center justify-between gap-4 shadow-xl animate-in fade-in zoom-in-95 duration-100">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-400">
              <CheckSquare className="w-4 h-4" />
              <span>{selectedIssueIds.length} Issues Selected</span>
            </div>

            <div className="flex items-center gap-2">
              {bulkPending && <Loader2 className="w-4 h-4 animate-spin" />}
              <button
                onClick={handleBulkAssignToMe}
                disabled={bulkPending}
                className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-60 text-white text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <UserCheck className="w-3.5 h-3.5" />
                Assign to Me
              </button>

              <button
                onClick={() => handleBulkResolve('fixed')}
                disabled={bulkPending}
                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-60 text-white text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Mark Fixed
              </button>

              <button
                onClick={() => handleBulkResolve('false-positive')}
                disabled={bulkPending}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-60 text-slate-200 text-xs font-bold rounded-lg transition-colors border border-slate-700"
              >
                False Positive
              </button>

              <button
                onClick={clearIssueSelections}
                className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-white underline font-medium"
              >
                Deselect
              </button>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          <div className="lg:col-span-1">
            <IssueFilters availableAssignees={availableAssignees} />
          </div>

          <div className="lg:col-span-3 space-y-4">
            <div className="bg-slate-100 rounded-xl px-4 py-2.5 flex items-center justify-between text-xs font-bold text-slate-700 border border-slate-200">
              <button
                onClick={() => {
                  if (isAllSelected) clearIssueSelections();
                  else selectAllIssues(allFilteredIds);
                }}
                className="flex items-center gap-2 hover:text-sky-700 transition-colors"
              >
                {isAllSelected ? <CheckSquare className="w-4 h-4 text-sky-600" /> : <Square className="w-4 h-4 text-slate-400" />}
                <span>Select All ({filteredIssues.length})</span>
              </button>

              <span>Total Technical Debt: <b>{formatDuration(totalDebtMinutes)}</b></span>
            </div>

            {isLoading ? (
              <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-xs flex items-center justify-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                Loading issues...
              </div>
            ) : filteredIssues.length === 0 ? (
              <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-xs">
                <p className="text-base font-semibold text-slate-800">No issues match the selected filters.</p>
                <p className="text-xs text-slate-500 mt-1">Try resetting severity/type filters or search terms.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {filteredIssues.map((issue) => (
                  <IssueItem
                    key={issue.id}
                    issue={issue}
                    isSelected={selectedIssueIds.includes(issue.id)}
                    onToggleSelect={toggleIssueSelection}
                    onIssueUpdated={handleIssueUpdated}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
