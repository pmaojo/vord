import React, { useMemo, useState } from 'react';
import { useRules } from '../../../lib/queries';
import { SeverityIcon } from '../../../components/common/SeverityIcon';
import { Search, BookOpen, Clock, Tag, ShieldAlert, Loader2 } from 'lucide-react';
import { IssueSeverity } from '../../../types';
import { formatDuration } from '../../../lib/utils';

/// Rule ids are namespaced as `<category>:<name>` (e.g. `owasp:eval-usage`,
/// `iac:public-s3-bucket`) — there is no separate language field on the real
/// rule catalog, so the category prefix is the only honest thing to filter by.
function categoryOf(ruleId: string): string {
  return ruleId.split(':')[0] || 'other';
}

export const RulesCatalogView: React.FC = () => {
  const { data: rules, isLoading, isError, error } = useRules();
  const [query, setQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');

  const categories = useMemo(() => {
    if (!rules) return [];
    return Array.from(new Set(rules.map((r) => categoryOf(r.id)))).sort();
  }, [rules]);

  const filteredRules = (rules ?? []).filter((rule) => {
    if (
      query &&
      !rule.id.toLowerCase().includes(query.toLowerCase()) &&
      !rule.description.toLowerCase().includes(query.toLowerCase())
    ) {
      return false;
    }
    if (selectedCategory !== 'ALL' && categoryOf(rule.id) !== selectedCategory) {
      return false;
    }
    return true;
  });

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2">
            <BookOpen className="w-7 h-7 text-sky-600" />
            <span>Coding Rules Catalog</span>
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            The live rule catalog served by this yunq instance's analyzers.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search rules by id or description..."
              className="w-full bg-white border border-slate-300 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>

          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-semibold"
          >
            <option value="ALL">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-slate-500 py-12 justify-center">
          <Loader2 className="w-4 h-4 animate-spin" />
          Loading rule catalog...
        </div>
      )}

      {isError && (
        <div className="bg-rose-50 border border-rose-200 text-rose-800 rounded-xl p-4 text-sm">
          Failed to load rules: {error instanceof Error ? error.message : 'unknown error'}
        </div>
      )}

      {!isLoading && !isError && filteredRules.length === 0 && (
        <div className="text-center text-sm text-slate-400 py-12">No rules match the current filters.</div>
      )}

      <div className="space-y-4">
        {filteredRules.map((rule) => (
          <div
            key={rule.id}
            className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs hover:border-slate-300 transition-colors"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <SeverityIcon severity={rule.default_severity.toUpperCase() as IssueSeverity} showText />
                <span className="text-slate-300">•</span>
                <span className="text-xs font-mono font-bold text-sky-700 bg-sky-50 px-2 py-0.5 rounded border border-sky-200">
                  {rule.id}
                </span>
                <span className="text-xs font-bold text-slate-600 bg-slate-100 px-2 py-0.5 rounded">
                  {categoryOf(rule.id)}
                </span>
                {rule.produces_hotspots && (
                  <span className="text-xs font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 flex items-center gap-1">
                    <ShieldAlert className="w-3 h-3" />
                    Security Hotspot
                  </span>
                )}
              </div>

              <span className="text-xs font-mono text-slate-500 flex items-center gap-1">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                Remediation Effort: {formatDuration(rule.remediation_effort_minutes)}
              </span>
            </div>

            <p className="text-xs text-slate-600 mt-3 leading-relaxed font-sans">{rule.description}</p>

            <div className="flex flex-wrap items-center gap-1.5 mt-3 pt-3 border-t border-slate-100">
              <Tag className="w-3.5 h-3.5 text-slate-400 mr-1" />
              {rule.tags.map((tag) => (
                <span
                  key={tag}
                  className="text-[10px] text-slate-600 bg-slate-100 px-2 py-0.5 rounded-full font-mono"
                >
                  #{tag}
                </span>
              ))}
              {typeof rule.cwe === 'number' && (
                <span className="text-[10px] text-indigo-700 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded-full font-mono ml-auto">
                  CWE-{rule.cwe}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
