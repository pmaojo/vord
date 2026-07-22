import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { MOCK_ISSUES, MOCK_PROJECTS } from '../../../testing/mock-data';
import { fetchIssuesFromApi } from '../../../lib/api';
import { useIssuesStore } from '../stores/useIssuesStore';
import { IssueItem } from './IssueItem';
import { IssueFilters } from './IssueFilters';
import { ProjectHeader } from '../../../components/layout/ProjectHeader';
import { Issue, IssueStatus, IssueSeverity } from '../../../types';
import { Search, UserCheck, Shield, CheckCircle, Tag, CheckSquare, Square } from 'lucide-react';

export const IssuesWorkspace: React.FC = () => {
  const { projectKey } = useParams<{ projectKey: string }>();
  const decodedProjectKey = projectKey ? decodeURIComponent(projectKey) : null;

  const project = decodedProjectKey
    ? MOCK_PROJECTS.find((p) => p.key === decodedProjectKey)
    : null;

  const [currentBranch, setCurrentBranch] = useState(
    project ? project.branches.find((b) => b.isMain)?.name || 'main' : 'main'
  );

  const [issuesList, setIssuesList] = useState<Issue[]>(MOCK_ISSUES);

  useEffect(() => {
    fetchIssuesFromApi()
      .then((data) => {
        if (data && data.items && data.items.length > 0) {
          const apiMapped: Issue[] = data.items.map((item) => ({
            id: item.id.toString(),
            key: `ISSUE-${item.id}`,
            ruleKey: item.rule,
            ruleName: item.rule,
            severity: (item.severity.toUpperCase() as IssueSeverity) || 'MAJOR',
            type: 'CODE_SMELL',
            status: (item.status.toUpperCase() as IssueStatus) || 'OPEN',
            message: item.message,
            component: item.file,
            projectKey: decodedProjectKey || 'yunq-core-platform',
            projectName: 'yunq-core-platform',
            line: item.line,
            creationDate: new Date().toISOString(),
            updateDate: new Date().toISOString(),
            effortMinutes: 10,
            assignee: item.assignee,
            author: 'yunq-analyzer',
            tags: ['sast'],
          }));
          setIssuesList(apiMapped);
        }
      })
      .catch(() => {
        // Fallback to initial dataset if server is initializing
      });
  }, [decodedProjectKey]);

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

  // Filter Issues
  const filteredIssues = issuesList.filter((issue) => {
    if (decodedProjectKey && issue.projectKey !== decodedProjectKey) {
      return false;
    }
    if (
      searchQuery &&
      !issue.message.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !issue.ruleKey.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !issue.component.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    if (selectedTypes.length > 0 && !selectedTypes.includes(issue.type)) {
      return false;
    }
    if (selectedSeverities.length > 0 && !selectedSeverities.includes(issue.severity)) {
      return false;
    }
    if (selectedStatuses.length > 0 && !selectedStatuses.includes(issue.status)) {
      return false;
    }
    if (assigneeFilter === 'UNASSIGNED' && issue.assignee) {
      return false;
    }
    if (assigneeFilter !== 'ALL' && assigneeFilter !== 'UNASSIGNED' && issue.assignee !== assigneeFilter) {
      return false;
    }
    return true;
  });

  const handleUpdateStatus = (issueId: string, newStatus: IssueStatus) => {
    setIssuesList((prev) =>
      prev.map((item) => (item.id === issueId ? { ...item, status: newStatus } : item))
    );
  };

  const handleUpdateSeverity = (issueId: string, newSeverity: IssueSeverity) => {
    setIssuesList((prev) =>
      prev.map((item) => (item.id === issueId ? { ...item, severity: newSeverity } : item))
    );
  };

  const handleBulkAssignToMe = () => {
    setIssuesList((prev) =>
      prev.map((item) => (selectedIssueIds.includes(item.id) ? { ...item, assignee: 'Administrator' } : item))
    );
    clearIssueSelections();
  };

  const handleBulkSetStatus = (status: IssueStatus) => {
    setIssuesList((prev) =>
      prev.map((item) => (selectedIssueIds.includes(item.id) ? { ...item, status } : item))
    );
    clearIssueSelections();
  };

  const allFilteredIds = filteredIssues.map((i) => i.id);
  const isAllSelected = allFilteredIds.length > 0 && allFilteredIds.every((id) => selectedIssueIds.includes(id));

  return (
    <div>
      {/* If in project context, render ProjectHeader */}
      {project && (
        <ProjectHeader
          project={project}
          currentBranch={currentBranch}
          onBranchChange={setCurrentBranch}
        />
      )}

      <div className="max-w-7xl mx-auto px-4 py-8">
        {/* Workspace Title & Search Header */}
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

        {/* Bulk Actions Floating Bar */}
        {selectedIssueIds.length > 0 && (
          <div className="mb-6 bg-slate-900 text-white rounded-xl p-3 px-5 flex flex-wrap items-center justify-between gap-4 shadow-xl animate-in fade-in zoom-in-95 duration-100">
            <div className="flex items-center gap-2 text-xs font-bold text-sky-400">
              <CheckSquare className="w-4 h-4" />
              <span>{selectedIssueIds.length} Issues Selected</span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleBulkAssignToMe}
                className="px-3 py-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <UserCheck className="w-3.5 h-3.5" />
                Assign to Me
              </button>

              <button
                onClick={() => handleBulkSetStatus('RESOLVED')}
                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                Mark Resolved
              </button>

              <button
                onClick={() => handleBulkSetStatus('FALSE_POSITIVE')}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold rounded-lg transition-colors border border-slate-700"
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

        {/* Main Grid: Filters + List */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar Filters */}
          <div className="lg:col-span-1">
            <IssueFilters />
          </div>

          {/* Issues List */}
          <div className="lg:col-span-3 space-y-4">
            {/* Select All Bar */}
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

              <span>Total Technical Debt: <b>14h 20m</b></span>
            </div>

            {filteredIssues.length === 0 ? (
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
                    onUpdateStatus={handleUpdateStatus}
                    onUpdateSeverity={handleUpdateSeverity}
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
