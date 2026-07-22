import React, { useState } from 'react';
import { Issue, IssueStatus, IssueSeverity } from '../../../types';
import { SeverityIcon } from '../../../components/common/SeverityIcon';
import { TypeIcon } from '../../../components/common/TypeIcon';
import { formatTimeAgo, formatDuration } from '../../../lib/utils';
import {
  ChevronDown,
  ChevronRight,
  Clock,
  User,
  FileCode,
  Sparkles,
  GitCommit,
  CheckCircle,
  XCircle,
  HelpCircle,
  Tag
} from 'lucide-react';
import { cn } from '../../../lib/utils';

interface IssueItemProps {
  issue: Issue;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onUpdateStatus?: (issueId: string, newStatus: IssueStatus) => void;
  onUpdateSeverity?: (issueId: string, newSeverity: IssueSeverity) => void;
}

export const IssueItem: React.FC<IssueItemProps> = ({
  issue,
  isSelected,
  onToggleSelect,
  onUpdateStatus,
  onUpdateSeverity,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState<'CODE' | 'DATAFLOW' | 'RULE'>('CODE');
  const [currentStatus, setCurrentStatus] = useState<IssueStatus>(issue.status);
  const [currentSeverity, setCurrentSeverity] = useState<IssueSeverity>(issue.severity);

  const handleStatusChange = (newStatus: IssueStatus) => {
    setCurrentStatus(newStatus);
    if (onUpdateStatus) onUpdateStatus(issue.id, newStatus);
  };

  const handleSeverityChange = (newSeverity: IssueSeverity) => {
    setCurrentSeverity(newSeverity);
    if (onUpdateSeverity) onUpdateSeverity(issue.id, newSeverity);
  };

  return (
    <div
      className={cn(
        'bg-white rounded-xl border transition-all duration-150 overflow-hidden shadow-2xs',
        isSelected ? 'border-sky-500 ring-1 ring-sky-500' : 'border-slate-200 hover:border-slate-300'
      )}
    >
      {/* Main Row Summary */}
      <div className="p-4 flex flex-wrap items-start justify-between gap-3 bg-white">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          {/* Checkbox for bulk action */}
          <input
            type="checkbox"
            checked={isSelected}
            onChange={() => onToggleSelect(issue.id)}
            className="mt-1 w-4 h-4 rounded text-sky-600 focus:ring-sky-500 border-slate-300 cursor-pointer"
          />

          {/* Expand trigger button */}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="mt-0.5 p-0.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded transition-colors"
          >
            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>

          {/* Details */}
          <div className="space-y-1 min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <TypeIcon type={issue.type} showText />
              <span className="text-slate-300">•</span>
              {/* Severity Dropdown */}
              <select
                value={currentSeverity}
                onChange={(e) => handleSeverityChange(e.target.value as IssueSeverity)}
                className="bg-slate-50 border border-slate-200 text-xs font-semibold rounded px-1.5 py-0.5 cursor-pointer hover:bg-slate-100"
              >
                <option value="BLOCKER">Blocker</option>
                <option value="CRITICAL">Critical</option>
                <option value="MAJOR">Major</option>
                <option value="MINOR">Minor</option>
                <option value="INFO">Info</option>
              </select>

              <span className="text-slate-300">•</span>
              <span className="text-xs font-mono font-bold text-sky-700 hover:underline cursor-pointer">
                {issue.ruleKey}
              </span>
              <span className="text-slate-300">•</span>
              <span className="text-xs font-mono text-slate-500 truncate">{issue.projectName}</span>
            </div>

            {/* Issue Message */}
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-sm font-bold text-slate-900 hover:text-sky-700 text-left leading-snug block cursor-pointer"
            >
              {issue.message}
            </button>

            {/* File & Line Location */}
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 font-mono pt-0.5">
              <span className="flex items-center gap-1 text-slate-700 font-semibold bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                <FileCode className="w-3.5 h-3.5 text-slate-400" />
                {issue.component}:{issue.line}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-slate-400" />
                Effort: {formatDuration(issue.effortMinutes)}
              </span>
              <span className="flex items-center gap-1">
                <User className="w-3 h-3 text-slate-400" />
                {issue.assignee || 'Unassigned'}
              </span>
              <span>•</span>
              <span>{formatTimeAgo(issue.creationDate)}</span>
            </div>
          </div>
        </div>

        {/* Status Control */}
        <div className="flex items-center gap-2 shrink-0">
          <select
            value={currentStatus}
            onChange={(e) => handleStatusChange(e.target.value as IssueStatus)}
            className={cn(
              'text-xs font-bold px-2.5 py-1 rounded-lg border cursor-pointer shadow-2xs',
              currentStatus === 'OPEN' && 'bg-amber-50 text-amber-800 border-amber-300',
              currentStatus === 'CONFIRMED' && 'bg-sky-50 text-sky-800 border-sky-300',
              currentStatus === 'RESOLVED' && 'bg-emerald-50 text-emerald-800 border-emerald-300',
              currentStatus === 'FALSE_POSITIVE' && 'bg-slate-100 text-slate-700 border-slate-300',
              currentStatus === 'WONT_FIX' && 'bg-slate-100 text-slate-700 border-slate-300'
            )}
          >
            <option value="OPEN">Open</option>
            <option value="CONFIRMED">Confirmed</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
            <option value="WONT_FIX">Won't Fix</option>
          </select>
        </div>
      </div>

      {/* Expanded Code Snippet & Diagnostic Tabs */}
      {isExpanded && (
        <div className="border-t border-slate-200 bg-slate-50 p-4 space-y-4">
          {/* Sub Tab Navigation */}
          <div className="flex items-center space-x-2 border-b border-slate-200 pb-2 text-xs font-bold">
            <button
              onClick={() => setActiveTab('CODE')}
              className={cn(
                'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5',
                activeTab === 'CODE' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
              )}
            >
              <FileCode className="w-3.5 h-3.5" />
              Code Context ({issue.codeSnippet ? issue.codeSnippet.length : 0} lines)
            </button>

            {issue.dataFlowTrace && issue.dataFlowTrace.length > 0 && (
              <button
                onClick={() => setActiveTab('DATAFLOW')}
                className={cn(
                  'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5',
                  activeTab === 'DATAFLOW' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
                )}
              >
                <GitCommit className="w-3.5 h-3.5 text-teal-400" />
                Data Flow Analysis ({issue.dataFlowTrace.length} steps)
              </button>
            )}

            {issue.ruleDescription && (
              <button
                onClick={() => setActiveTab('RULE')}
                className={cn(
                  'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5',
                  activeTab === 'RULE' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
                )}
              >
                <HelpCircle className="w-3.5 h-3.5 text-sky-400" />
                Why is this an issue?
              </button>
            )}
          </div>

          {/* TAB 1: CODE SNIPPET VIEWER */}
          {activeTab === 'CODE' && (
            <div className="bg-slate-950 text-slate-100 rounded-xl overflow-hidden font-mono text-xs border border-slate-800 shadow-inner">
              <div className="bg-slate-900 px-4 py-2 text-slate-400 border-b border-slate-800 flex items-center justify-between">
                <span>{issue.component}</span>
                <span className="text-[10px] text-slate-500">Highlighting line {issue.line}</span>
              </div>
              <div className="p-2 overflow-x-auto divide-y divide-slate-900/50">
                {issue.codeSnippet?.map((line) => {
                  const isErrorLine = line.line === issue.line;
                  return (
                    <div
                      key={line.line}
                      className={cn(
                        'flex items-center px-2 py-1 font-mono hover:bg-slate-900/80 transition-colors',
                        isErrorLine && 'bg-rose-950/60 border-l-4 border-rose-500 text-rose-100'
                      )}
                    >
                      <span className="w-10 text-slate-600 select-none text-right pr-3 shrink-0">
                        {line.line}
                      </span>
                      <code className="whitespace-pre flex-1">{line.code}</code>
                    </div>
                  );
                })}
              </div>

              {/* Inline Issue Tooltip on Error Line */}
              <div className="bg-rose-900/40 border-t border-rose-700/60 px-4 py-2.5 text-xs text-rose-200 flex items-center gap-2">
                <SeverityIcon severity={issue.severity} />
                <span className="font-bold">{issue.ruleKey}:</span>
                <span>{issue.message}</span>
              </div>
            </div>
          )}

          {/* TAB 2: DATA FLOW ANALYSIS STEPPER */}
          {activeTab === 'DATAFLOW' && issue.dataFlowTrace && (
            <div className="bg-white rounded-xl border border-slate-200 p-4 space-y-3 shadow-2xs">
              <div className="text-xs font-bold text-slate-900 uppercase tracking-wider mb-2">
                Trace execution path from source to sink:
              </div>
              <div className="space-y-2">
                {issue.dataFlowTrace.map((step) => (
                  <div
                    key={step.step}
                    className="flex items-start gap-3 p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs font-mono"
                  >
                    <span className="w-6 h-6 rounded-full bg-slate-900 text-white font-bold flex items-center justify-center shrink-0">
                      {step.step}
                    </span>
                    <div className="flex-1 space-y-1">
                      <div className="flex items-center justify-between text-slate-500 text-[11px]">
                        <span>{step.file}:{step.line}</span>
                      </div>
                      <code className="block bg-slate-900 text-sky-300 p-2 rounded text-xs font-mono">
                        {step.code}
                      </code>
                      <p className="text-slate-700 font-sans font-medium text-xs pt-0.5">
                        {step.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: RULE DESCRIPTION & COMPLIANT EXAMPLES */}
          {activeTab === 'RULE' && issue.ruleDescription && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4 text-xs text-slate-800">
              <div>
                <h4 className="font-bold text-slate-900 text-sm mb-1">Why is this an issue?</h4>
                <p className="text-slate-600 leading-relaxed">{issue.ruleDescription.why}</p>
              </div>

              <div>
                <h4 className="font-bold text-slate-900 text-sm mb-1">How to fix it</h4>
                <p className="text-slate-600 leading-relaxed">{issue.ruleDescription.howToFix}</p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                {/* Non-compliant */}
                <div className="bg-rose-50 border border-rose-200 rounded-lg p-3">
                  <div className="flex items-center gap-1.5 font-bold text-rose-800 mb-1.5">
                    <XCircle className="w-4 h-4 text-rose-600" />
                    <span>Non-compliant Code Example</span>
                  </div>
                  <pre className="bg-slate-900 text-rose-200 p-2.5 rounded font-mono text-[11px] overflow-x-auto">
                    {issue.ruleDescription.nonCompliant}
                  </pre>
                </div>

                {/* Compliant */}
                <div className="bg-emerald-50 border border-emerald-200 rounded-lg p-3">
                  <div className="flex items-center gap-1.5 font-bold text-emerald-800 mb-1.5">
                    <CheckCircle className="w-4 h-4 text-emerald-600" />
                    <span>Compliant Solution</span>
                  </div>
                  <pre className="bg-slate-900 text-emerald-200 p-2.5 rounded font-mono text-[11px] overflow-x-auto">
                    {issue.ruleDescription.compliant}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
