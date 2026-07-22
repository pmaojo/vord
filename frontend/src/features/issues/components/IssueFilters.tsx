import React from 'react';
import { useIssuesStore } from '../stores/useIssuesStore';
import { IssueType, IssueSeverity, IssueStatus } from '../../../types';
import { SeverityIcon } from '../../../components/common/SeverityIcon';
import { TypeIcon } from '../../../components/common/TypeIcon';
import { Filter, RotateCcw, Check } from 'lucide-react';
import { cn } from '../../../lib/utils';

export const IssueFilters: React.FC = () => {
  const {
    selectedTypes,
    toggleType,
    selectedSeverities,
    toggleSeverity,
    selectedStatuses,
    toggleStatus,
    assigneeFilter,
    setAssigneeFilter,
    resetFilters,
  } = useIssuesStore();

  const types: IssueType[] = ['BUG', 'VULNERABILITY', 'CODE_SMELL', 'SECURITY_HOTSPOT'];
  const severities: IssueSeverity[] = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO'];
  const statuses: IssueStatus[] = ['OPEN', 'CONFIRMED', 'RESOLVED', 'FALSE_POSITIVE', 'WONT_FIX'];

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-4 shadow-xs space-y-6">
      <div className="flex items-center justify-between border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2 font-bold text-slate-900 text-sm">
          <Filter className="w-4 h-4 text-sky-600" />
          <span>Issue Filters</span>
        </div>
        <button
          onClick={resetFilters}
          className="text-xs text-sky-600 hover:text-sky-800 font-medium flex items-center gap-1 hover:underline"
        >
          <RotateCcw className="w-3 h-3" />
          Reset
        </button>
      </div>

      {/* Type Filter */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Type
        </label>
        <div className="space-y-1">
          {types.map((type) => {
            const isChecked = selectedTypes.includes(type);
            return (
              <button
                key={type}
                onClick={() => toggleType(type)}
                className={cn(
                  'w-full flex items-center justify-between px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors',
                  isChecked
                    ? 'bg-sky-50 text-sky-800 border border-sky-200'
                    : 'text-slate-600 hover:bg-slate-50'
                )}
              >
                <TypeIcon type={type} showText />
                {isChecked && <Check className="w-3.5 h-3.5 text-sky-600" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Severity Filter */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Severity
        </label>
        <div className="space-y-1">
          {severities.map((severity) => {
            const isChecked = selectedSeverities.includes(severity);
            return (
              <button
                key={severity}
                onClick={() => toggleSeverity(severity)}
                className={cn(
                  'w-full flex items-center justify-between px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors',
                  isChecked
                    ? 'bg-sky-50 text-sky-800 border border-sky-200'
                    : 'text-slate-600 hover:bg-slate-50'
                )}
              >
                <SeverityIcon severity={severity} showText />
                {isChecked && <Check className="w-3.5 h-3.5 text-sky-600" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Status Filter */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Status
        </label>
        <div className="space-y-1">
          {statuses.map((status) => {
            const isChecked = selectedStatuses.includes(status);
            return (
              <button
                key={status}
                onClick={() => toggleStatus(status)}
                className={cn(
                  'w-full flex items-center justify-between px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors',
                  isChecked
                    ? 'bg-sky-50 text-sky-800 border border-sky-200'
                    : 'text-slate-600 hover:bg-slate-50'
                )}
              >
                <span className="capitalize">{status.toLowerCase().replace('_', ' ')}</span>
                {isChecked && <Check className="w-3.5 h-3.5 text-sky-600" />}
              </button>
            );
          })}
        </div>
      </div>

      {/* Assignee Filter */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Assignee
        </label>
        <select
          value={assigneeFilter}
          onChange={(e) => setAssigneeFilter(e.target.value)}
          className="w-full bg-slate-50 border border-slate-200 text-slate-800 text-xs rounded-lg px-2.5 py-2 font-medium focus:outline-none focus:ring-2 focus:ring-sky-500"
        >
          <option value="ALL">All Assignees</option>
          <option value="UNASSIGNED">Unassigned</option>
          <option value="Alex Mercer">Alex Mercer</option>
          <option value="Sarah Connor">Sarah Connor</option>
          <option value="David Miller">David Miller</option>
        </select>
      </div>
    </div>
  );
};
