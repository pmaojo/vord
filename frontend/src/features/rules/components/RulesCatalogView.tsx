import React, { useState } from 'react';
import { MOCK_RULES } from '../../../testing/mock-data';
import { SeverityIcon } from '../../../components/common/SeverityIcon';
import { TypeIcon } from '../../../components/common/TypeIcon';
import { Search, BookOpen, Clock, Tag } from 'lucide-react';

export const RulesCatalogView: React.FC = () => {
  const [query, setQuery] = useState('');
  const [selectedLanguage, setSelectedLanguage] = useState('ALL');

  const filteredRules = MOCK_RULES.filter((rule) => {
    if (
      query &&
      !rule.name.toLowerCase().includes(query.toLowerCase()) &&
      !rule.key.toLowerCase().includes(query.toLowerCase())
    ) {
      return false;
    }
    if (selectedLanguage !== 'ALL' && rule.lang !== selectedLanguage) {
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
            Browse static analysis rules for code quality, clean code standards, and security vulnerabilities.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="relative w-72">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search rules by name or key..."
              className="w-full bg-white border border-slate-300 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-800 focus:outline-none focus:ring-2 focus:ring-sky-500"
            />
          </div>

          <select
            value={selectedLanguage}
            onChange={(e) => setSelectedLanguage(e.target.value)}
            className="bg-white border border-slate-300 rounded-lg px-3 py-2 text-xs font-semibold"
          >
            <option value="ALL">All Languages</option>
            <option value="Java">Java</option>
            <option value="TypeScript">TypeScript</option>
            <option value="Go">Go</option>
            <option value="Python">Python</option>
          </select>
        </div>
      </div>

      <div className="space-y-4">
        {filteredRules.map((rule) => (
          <div
            key={rule.key}
            className="bg-white rounded-xl border border-slate-200 p-5 shadow-xs hover:border-slate-300 transition-colors"
          >
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <TypeIcon type={rule.type} showText />
                <span className="text-slate-300">•</span>
                <SeverityIcon severity={rule.severity} showText />
                <span className="text-slate-300">•</span>
                <span className="text-xs font-mono font-bold text-sky-700 bg-sky-50 px-2 py-0.5 rounded border border-sky-200">
                  {rule.key}
                </span>
                <span className="text-xs font-bold text-slate-600 bg-slate-100 px-2 py-0.5 rounded">
                  {rule.lang}
                </span>
              </div>

              <span className="text-xs font-mono text-slate-500 flex items-center gap-1">
                <Clock className="w-3.5 h-3.5 text-slate-400" />
                Remediation Effort: {rule.remediationEffort}
              </span>
            </div>

            <h3 className="text-base font-bold text-slate-900 mt-2">{rule.name}</h3>

            <div
              className="text-xs text-slate-600 mt-2 leading-relaxed font-sans"
              dangerouslySetInnerHTML={{ __html: rule.htmlDesc }}
            />

            <div className="flex flex-wrap items-center gap-1.5 mt-3 pt-3 border-t border-slate-100">
              <Tag className="w-3.5 h-3.5 text-slate-400 mr-1" />
              {rule.sysTags.map((tag) => (
                <span
                  key={tag}
                  className="text-[10px] text-slate-600 bg-slate-100 px-2 py-0.5 rounded-full font-mono"
                >
                  #{tag}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
