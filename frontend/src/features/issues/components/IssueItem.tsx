import React, { useState } from 'react';
import { Issue, IssueStatus } from '../../../types';
import { SeverityIcon } from '../../../components/common/SeverityIcon';
import { TypeIcon } from '../../../components/common/TypeIcon';
import { formatTimeAgo, formatDuration, cn } from '../../../lib/utils';
import {
  requestAiFix,
  AgentFixProposal,
  transitionIssue,
  assignIssue,
  fetchIssueChangelog,
  ApiChangelogEntry,
} from '../../../lib/api';
import { mapApiIssueToIssue } from '../mapIssue';
import { useRules } from '../../../lib/queries';
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
  Loader2,
  Lock,
  History,
  Check,
  RotateCcw,
  Ban,
  Pencil,
} from 'lucide-react';

interface IssueItemProps {
  issue: Issue;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onIssueUpdated?: (issue: Issue) => void;
}

/// The real workflow: Open --confirm--> Confirmed; Open/Confirmed --resolve--> Resolved;
/// Resolved --reopen--> Open; Resolved --close--> Closed. Everything else is a 409.
function availableTransitions(status: IssueStatus): Array<'confirm' | 'resolve' | 'reopen' | 'close'> {
  switch (status) {
    case 'OPEN':
      return ['confirm', 'resolve'];
    case 'CONFIRMED':
      return ['resolve'];
    case 'RESOLVED':
      return ['reopen', 'close'];
    case 'CLOSED':
      return [];
  }
}

export const IssueItem: React.FC<IssueItemProps> = ({ issue, isSelected, onToggleSelect, onIssueUpdated }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState<'CODE' | 'DATAFLOW' | 'RULE' | 'REMEDIATION' | 'HISTORY'>('CODE');
  const { data: rules } = useRules();

  const [transitionPending, setTransitionPending] = useState(false);
  const [transitionError, setTransitionError] = useState<string | null>(null);
  const [resolvePickerOpen, setResolvePickerOpen] = useState(false);

  const [isEditingAssignee, setIsEditingAssignee] = useState(false);
  const [assigneeDraft, setAssigneeDraft] = useState(issue.assignee ?? '');
  const [assigneePending, setAssigneePending] = useState(false);

  const [aiFix, setAiFix] = useState<AgentFixProposal | null>(null);
  const [aiFixLoading, setAiFixLoading] = useState(false);
  const [aiFixError, setAiFixError] = useState<string | null>(null);
  const [upgradeRequired, setUpgradeRequired] = useState(false);

  const [changelog, setChangelog] = useState<ApiChangelogEntry[] | null>(null);
  const [changelogLoading, setChangelogLoading] = useState(false);
  const [changelogError, setChangelogError] = useState<string | null>(null);

  const ruleIndex = React.useMemo(() => new Map((rules ?? []).map((r) => [r.id, r])), [rules]);

  const applyServerIssue = (apiIssue: Parameters<typeof mapApiIssueToIssue>[0]) => {
    const updated = mapApiIssueToIssue(apiIssue, issue.projectKey, ruleIndex);
    onIssueUpdated?.({ ...issue, ...updated });
  };

  const handleTransition = async (
    transition: 'confirm' | 'resolve' | 'reopen' | 'close',
    resolution?: 'fixed' | 'wont-fix' | 'false-positive'
  ) => {
    setTransitionPending(true);
    setTransitionError(null);
    setResolvePickerOpen(false);
    try {
      const updated = await transitionIssue(Number(issue.id), transition, resolution);
      applyServerIssue(updated);
    } catch (err) {
      setTransitionError(err instanceof Error ? err.message : 'Transition failed');
    } finally {
      setTransitionPending(false);
    }
  };

  const handleSaveAssignee = async () => {
    setAssigneePending(true);
    try {
      const updated = await assignIssue(Number(issue.id), assigneeDraft.trim() || null);
      applyServerIssue(updated);
      setIsEditingAssignee(false);
    } catch (err) {
      setTransitionError(err instanceof Error ? err.message : 'Assignment failed');
    } finally {
      setAssigneePending(false);
    }
  };

  const handleRequestAiFix = async () => {
    setAiFixLoading(true);
    setAiFixError(null);
    setUpgradeRequired(false);
    try {
      const proposal = await requestAiFix(Number(issue.id));
      setAiFix(proposal);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to generate AI fix';
      setUpgradeRequired(/pro or enterprise/i.test(message));
      setAiFixError(message);
    } finally {
      setAiFixLoading(false);
    }
  };

  const handleOpenHistory = async () => {
    setActiveTab('HISTORY');
    if (changelog !== null) return;
    setChangelogLoading(true);
    setChangelogError(null);
    try {
      const entries = await fetchIssueChangelog(Number(issue.id));
      setChangelog(entries);
    } catch (err) {
      setChangelogError(err instanceof Error ? err.message : 'Failed to load history');
    } finally {
      setChangelogLoading(false);
    }
  };

  const transitions = availableTransitions(issue.status);

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
          <input
            type="checkbox"
            checked={isSelected}
            onChange={() => onToggleSelect(issue.id)}
            className="mt-1 w-4 h-4 rounded text-sky-600 focus:ring-sky-500 border-slate-300 cursor-pointer"
          />

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="mt-0.5 p-0.5 text-slate-400 hover:text-slate-700 hover:bg-slate-100 rounded transition-colors"
          >
            {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
          </button>

          <div className="space-y-1 min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <TypeIcon type={issue.type} showText />
              <span className="text-slate-300">•</span>
              <SeverityIcon severity={issue.severity} showText />
              <span className="text-slate-300">•</span>
              <span className="text-xs font-mono font-bold text-sky-700">{issue.ruleKey}</span>
              <span className="text-slate-300">•</span>
              <span className="text-xs font-mono text-slate-500 truncate">{issue.projectName}</span>
              {issue.resolution && (
                <span className="text-[10px] font-bold uppercase text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                  {issue.resolution.replace('_', ' ')}
                </span>
              )}
            </div>

            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-sm font-bold text-slate-900 hover:text-sky-700 text-left leading-snug block cursor-pointer"
            >
              {issue.message}
            </button>

            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 font-mono pt-0.5">
              <span className="flex items-center gap-1 text-slate-700 font-semibold bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
                <FileCode className="w-3.5 h-3.5 text-slate-400" />
                {issue.component}:{issue.line}
              </span>
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3 text-slate-400" />
                Effort: {formatDuration(issue.effortMinutes)}
              </span>

              {isEditingAssignee ? (
                <span className="flex items-center gap-1">
                  <User className="w-3 h-3 text-slate-400" />
                  <input
                    autoFocus
                    value={assigneeDraft}
                    onChange={(e) => setAssigneeDraft(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleSaveAssignee()}
                    placeholder="username"
                    className="bg-white border border-slate-300 rounded px-1.5 py-0.5 text-xs font-mono w-28"
                  />
                  <button
                    onClick={handleSaveAssignee}
                    disabled={assigneePending}
                    className="text-emerald-600 hover:text-emerald-800 disabled:opacity-50"
                  >
                    {assigneePending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
                  </button>
                </span>
              ) : (
                <button
                  onClick={() => {
                    setAssigneeDraft(issue.assignee ?? '');
                    setIsEditingAssignee(true);
                  }}
                  className="flex items-center gap-1 hover:text-sky-700 group"
                >
                  <User className="w-3 h-3 text-slate-400" />
                  {issue.assignee || 'Unassigned'}
                  <Pencil className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100" />
                </button>
              )}
              <span>•</span>
              <span>{formatTimeAgo(issue.creationDate)}</span>
            </div>

            {transitionError && (
              <div className="text-[11px] text-rose-700 bg-rose-50 border border-rose-200 rounded px-2 py-1 mt-1 inline-block">
                {transitionError}
              </div>
            )}
          </div>
        </div>

        {/* Status + Transition Controls */}
        <div className="flex items-center gap-1.5 shrink-0 relative">
          <span
            className={cn(
              'text-xs font-bold px-2.5 py-1 rounded-lg border shadow-2xs',
              issue.status === 'OPEN' && 'bg-amber-50 text-amber-800 border-amber-300',
              issue.status === 'CONFIRMED' && 'bg-sky-50 text-sky-800 border-sky-300',
              issue.status === 'RESOLVED' && 'bg-emerald-50 text-emerald-800 border-emerald-300',
              issue.status === 'CLOSED' && 'bg-slate-100 text-slate-700 border-slate-300'
            )}
          >
            {issue.status.charAt(0) + issue.status.slice(1).toLowerCase()}
          </span>

          {transitionPending && <Loader2 className="w-4 h-4 animate-spin text-slate-400" />}

          {!transitionPending &&
            transitions.map((t) =>
              t === 'resolve' ? (
                <div key="resolve" className="relative">
                  <button
                    onClick={() => setResolvePickerOpen((v) => !v)}
                    className="text-xs font-bold px-2 py-1 rounded-lg border border-emerald-300 text-emerald-700 hover:bg-emerald-50 flex items-center gap-1"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    Resolve
                  </button>
                  {resolvePickerOpen && (
                    <div className="absolute right-0 mt-1 bg-white border border-slate-200 rounded-lg shadow-lg z-10 py-1 w-36">
                      <button
                        onClick={() => handleTransition('resolve', 'fixed')}
                        className="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50"
                      >
                        Fixed
                      </button>
                      <button
                        onClick={() => handleTransition('resolve', 'wont-fix')}
                        className="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50"
                      >
                        Won't Fix
                      </button>
                      <button
                        onClick={() => handleTransition('resolve', 'false-positive')}
                        className="w-full text-left px-3 py-1.5 text-xs hover:bg-slate-50"
                      >
                        False Positive
                      </button>
                    </div>
                  )}
                </div>
              ) : (
                <button
                  key={t}
                  onClick={() => handleTransition(t)}
                  className="text-xs font-bold px-2 py-1 rounded-lg border border-slate-300 text-slate-700 hover:bg-slate-50 flex items-center gap-1"
                >
                  {t === 'confirm' && <Check className="w-3.5 h-3.5" />}
                  {t === 'reopen' && <RotateCcw className="w-3.5 h-3.5" />}
                  {t === 'close' && <Ban className="w-3.5 h-3.5" />}
                  {t.charAt(0).toUpperCase() + t.slice(1)}
                </button>
              )
            )}
        </div>
      </div>

      {/* Expanded Code Snippet & Diagnostic Tabs */}
      {isExpanded && (
        <div className="border-t border-slate-200 bg-slate-50 p-4 space-y-4">
          <div className="flex items-center space-x-2 border-b border-slate-200 pb-2 text-xs font-bold overflow-x-auto">
            <button
              onClick={() => setActiveTab('CODE')}
              className={cn(
                'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 shrink-0',
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
                  'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 shrink-0',
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
                  'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 shrink-0',
                  activeTab === 'RULE' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
                )}
              >
                <HelpCircle className="w-3.5 h-3.5 text-sky-400" />
                Why is this an issue?
              </button>
            )}

            <button
              onClick={() => setActiveTab('REMEDIATION')}
              className={cn(
                'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 shrink-0',
                activeTab === 'REMEDIATION' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
              )}
            >
              <Sparkles className="w-3.5 h-3.5 text-violet-400" />
              AI Remediation
            </button>

            <button
              onClick={handleOpenHistory}
              className={cn(
                'px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 shrink-0',
                activeTab === 'HISTORY' ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-200'
              )}
            >
              <History className="w-3.5 h-3.5 text-amber-400" />
              History
            </button>
          </div>

          {activeTab === 'CODE' && (
            <div className="bg-slate-950 text-slate-100 rounded-xl overflow-hidden font-mono text-xs border border-slate-800 shadow-inner">
              <div className="bg-slate-900 px-4 py-2 text-slate-400 border-b border-slate-800 flex items-center justify-between">
                <span>{issue.component}</span>
                <span className="text-[10px] text-slate-500">Highlighting line {issue.line}</span>
              </div>
              {issue.codeSnippet && issue.codeSnippet.length > 0 ? (
                <div className="p-2 overflow-x-auto divide-y divide-slate-900/50">
                  {issue.codeSnippet.map((line) => {
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
              ) : (
                <div className="p-4 text-slate-500 text-xs">
                  No source snippet available for this issue.
                </div>
              )}

              <div className="bg-rose-900/40 border-t border-rose-700/60 px-4 py-2.5 text-xs text-rose-200 flex items-center gap-2">
                <SeverityIcon severity={issue.severity} />
                <span className="font-bold">{issue.ruleKey}:</span>
                <span>{issue.message}</span>
              </div>
            </div>
          )}

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
                      <p className="text-slate-700 font-sans font-medium text-xs pt-0.5">{step.description}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

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
                <div className="bg-rose-50 border border-rose-200 rounded-lg p-3">
                  <div className="flex items-center gap-1.5 font-bold text-rose-800 mb-1.5">
                    <XCircle className="w-4 h-4 text-rose-600" />
                    <span>Non-compliant Code Example</span>
                  </div>
                  <pre className="bg-slate-900 text-rose-200 p-2.5 rounded font-mono text-[11px] overflow-x-auto">
                    {issue.ruleDescription.nonCompliant}
                  </pre>
                </div>

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

          {activeTab === 'REMEDIATION' && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-4 text-xs text-slate-800">
              {!aiFix && (
                <div className="flex flex-col items-start gap-3">
                  <p className="text-slate-600 leading-relaxed">
                    Generate an AI-proposed code fix for this issue. Only fixes that pass a real
                    generate → sandbox → re-scan → verdict loop are ever returned.
                  </p>
                  <button
                    onClick={handleRequestAiFix}
                    disabled={aiFixLoading}
                    className="px-3 py-1.5 bg-violet-600 hover:bg-violet-500 disabled:opacity-60 disabled:cursor-not-allowed text-white text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-2xs"
                  >
                    {aiFixLoading ? (
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <Sparkles className="w-3.5 h-3.5" />
                    )}
                    {aiFixLoading ? 'Generating fix...' : 'Generate AI Fix'}
                  </button>

                  {aiFixError && (
                    <div
                      className={cn(
                        'w-full rounded-lg border p-3 flex items-start gap-2',
                        upgradeRequired
                          ? 'bg-amber-50 border-amber-200 text-amber-800'
                          : 'bg-rose-50 border-rose-200 text-rose-800'
                      )}
                    >
                      {upgradeRequired ? (
                        <Lock className="w-4 h-4 shrink-0 mt-0.5" />
                      ) : (
                        <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
                      )}
                      <span>{aiFixError}</span>
                    </div>
                  )}
                </div>
              )}

              {aiFix && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 font-bold text-violet-800">
                      <Sparkles className="w-4 h-4 text-violet-600" />
                      <span>Proposed Fix</span>
                      {aiFix.verified && (
                        <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded">
                          Verified
                        </span>
                      )}
                    </div>
                    <button
                      onClick={handleRequestAiFix}
                      disabled={aiFixLoading}
                      className="text-[11px] font-bold text-violet-700 hover:text-violet-900 disabled:opacity-60 flex items-center gap-1"
                    >
                      {aiFixLoading ? (
                        <Loader2 className="w-3 h-3 animate-spin" />
                      ) : (
                        <Sparkles className="w-3 h-3" />
                      )}
                      Regenerate
                    </button>
                  </div>

                  <p className="text-slate-600 leading-relaxed">{aiFix.explanation}</p>

                  <pre className="bg-slate-950 text-emerald-200 p-3 rounded-lg font-mono text-[11px] overflow-x-auto border border-slate-800">
                    {aiFix.modified_code}
                  </pre>
                </div>
              )}
            </div>
          )}

          {activeTab === 'HISTORY' && (
            <div className="bg-white rounded-xl border border-slate-200 p-5 space-y-3 text-xs text-slate-800">
              {changelogLoading && (
                <div className="flex items-center gap-2 text-slate-500 py-4 justify-center">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Loading history...
                </div>
              )}
              {changelogError && <div className="text-rose-700">{changelogError}</div>}
              {!changelogLoading && changelog && changelog.length === 0 && (
                <div className="text-slate-400 text-center py-4">No workflow history yet.</div>
              )}
              {!changelogLoading &&
                changelog?.map((entry, idx) => (
                  <div key={idx} className="flex items-center justify-between border-b border-slate-100 py-2 font-mono">
                    <span>
                      {entry.action === 'transitioned'
                        ? `${entry.from_status} → ${entry.transition}${entry.resolution ? ` (${entry.resolution})` : ''}`
                        : `assigned → ${entry.assignee ?? 'unassigned'}`}
                    </span>
                    <span className="text-slate-400">{formatTimeAgo(entry.at)}</span>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
