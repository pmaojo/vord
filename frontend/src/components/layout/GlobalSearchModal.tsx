import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useGlobalStore } from '../../stores/global-store';
import { MOCK_PROJECTS, MOCK_ISSUES, MOCK_RULES } from '../../testing/mock-data';
import { Search, FolderGit2, AlertCircle, BookOpen, X, ChevronRight } from 'lucide-react';

export const GlobalSearchModal: React.FC = () => {
  const { isSearchOpen, setSearchOpen } = useGlobalStore();
  const [query, setQuery] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(!isSearchOpen);
      }
      if (e.key === 'Escape' && isSearchOpen) {
        setSearchOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSearchOpen, setSearchOpen]);

  if (!isSearchOpen) return null;

  const filteredProjects = MOCK_PROJECTS.filter(
    (p) => p.name.toLowerCase().includes(query.toLowerCase()) || p.key.toLowerCase().includes(query.toLowerCase())
  );

  const filteredIssues = MOCK_ISSUES.filter(
    (i) =>
      i.message.toLowerCase().includes(query.toLowerCase()) ||
      i.component.toLowerCase().includes(query.toLowerCase()) ||
      i.ruleKey.toLowerCase().includes(query.toLowerCase())
  );

  const filteredRules = MOCK_RULES.filter(
    (r) => r.name.toLowerCase().includes(query.toLowerCase()) || r.key.toLowerCase().includes(query.toLowerCase())
  );

  const handleSelectProject = (projectKey: string) => {
    setSearchOpen(false);
    navigate(`/projects/${encodeURIComponent(projectKey)}/overview`);
  };

  const handleSelectIssue = (projectKey: string) => {
    setSearchOpen(false);
    navigate(`/projects/${encodeURIComponent(projectKey)}/issues`);
  };

  const handleSelectRule = () => {
    setSearchOpen(false);
    navigate('/rules');
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-slate-950/60 backdrop-blur-xs p-4">
      <div className="bg-white rounded-xl shadow-2xl border border-slate-200 w-full max-w-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Input area */}
        <div className="flex items-center px-4 py-3 border-b border-slate-200 gap-3">
          <Search className="w-5 h-5 text-slate-400 shrink-0" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search projects, issues, files, rules... (e.g. 'auth', 'SQL')"
            className="w-full text-base outline-none text-slate-800 placeholder:text-slate-400 bg-transparent"
          />
          <button
            onClick={() => setSearchOpen(false)}
            className="p-1 text-slate-400 hover:text-slate-600 rounded-lg hover:bg-slate-100"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Results Area */}
        <div className="max-h-96 overflow-y-auto p-2 divide-y divide-slate-100">
          {/* Projects */}
          {filteredProjects.length > 0 && (
            <div className="p-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 mb-1 flex items-center gap-1.5">
                <FolderGit2 className="w-3.5 h-3.5" />
                Projects ({filteredProjects.length})
              </div>
              {filteredProjects.map((project) => (
                <button
                  key={project.key}
                  onClick={() => handleSelectProject(project.key)}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-sky-50 transition-colors flex items-center justify-between group"
                >
                  <div>
                    <div className="text-sm font-semibold text-slate-800 group-hover:text-sky-700">
                      {project.name}
                    </div>
                    <div className="text-xs text-slate-500 font-mono">{project.key}</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-sky-600" />
                </button>
              ))}
            </div>
          )}

          {/* Issues */}
          {filteredIssues.length > 0 && (
            <div className="p-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 mb-1 flex items-center gap-1.5">
                <AlertCircle className="w-3.5 h-3.5" />
                Issues ({filteredIssues.length})
              </div>
              {filteredIssues.map((issue) => (
                <button
                  key={issue.id}
                  onClick={() => handleSelectIssue(issue.projectKey)}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-sky-50 transition-colors flex items-center justify-between group"
                >
                  <div className="max-w-md">
                    <div className="text-xs font-mono text-slate-500">{issue.ruleKey} • {issue.component}</div>
                    <div className="text-sm text-slate-800 truncate group-hover:text-sky-700 font-medium">
                      {issue.message}
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-sky-600 shrink-0" />
                </button>
              ))}
            </div>
          )}

          {/* Rules */}
          {filteredRules.length > 0 && (
            <div className="p-2">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider px-2 mb-1 flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5" />
                Rules ({filteredRules.length})
              </div>
              {filteredRules.map((rule) => (
                <button
                  key={rule.key}
                  onClick={handleSelectRule}
                  className="w-full text-left px-3 py-2 rounded-lg hover:bg-sky-50 transition-colors flex items-center justify-between group"
                >
                  <div>
                    <div className="text-sm font-medium text-slate-800 group-hover:text-sky-700">
                      {rule.name}
                    </div>
                    <div className="text-xs text-slate-500 font-mono">{rule.key} ({rule.lang})</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-300 group-hover:text-sky-600" />
                </button>
              ))}
            </div>
          )}

          {filteredProjects.length === 0 && filteredIssues.length === 0 && filteredRules.length === 0 && (
            <div className="py-12 text-center text-slate-500 text-sm">
              No matching projects, issues, or rules found for "{query}".
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="bg-slate-50 px-4 py-2 border-t border-slate-200 text-xs text-slate-500 flex justify-between items-center">
          <span>Navigate with <b>↑</b> <b>↓</b></span>
          <span>Press <b>ESC</b> to close</span>
        </div>
      </div>
    </div>
  );
};
