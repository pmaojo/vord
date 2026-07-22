import React from 'react';
import { useProjectsStore } from '../stores/useProjectsStore';
import { QualityGateStatus, Rating } from '../../../types';
import { Filter, RotateCcw, Check } from 'lucide-react';
import { cn } from '../../../lib/utils';

export const ProjectFilters: React.FC = () => {
  const {
    qualityGateStatus,
    setQualityGateStatus,
    reliabilityRating,
    setReliabilityRating,
    securityRating,
    setSecurityRating,
    selectedLanguage,
    setSelectedLanguage,
    selectedTag,
    setSelectedTag,
    resetFilters,
  } = useProjectsStore();

  const languages = ['ALL', 'Java', 'TypeScript', 'Go', 'Python'];
  const tags = ['ALL', 'core', 'payments', 'auth', 'data', 'frontend'];
  const ratings: Rating[] = ['A', 'B', 'C', 'D', 'E'];

  return (
    <div className="bg-white rounded border border-gray-200 p-4 shadow-2xs space-y-6">
      <div className="flex items-center justify-between border-b border-gray-100 pb-3">
        <div className="flex items-center gap-2 font-bold text-[#233445] text-xs uppercase tracking-wider">
          <Filter className="w-3.5 h-3.5 text-[#4b9fd5]" />
          <span>Filters</span>
        </div>
        <button
          onClick={resetFilters}
          className="text-xs text-[#4b9fd5] hover:underline font-medium flex items-center gap-1"
        >
          <RotateCcw className="w-3 h-3" />
          Reset
        </button>
      </div>

      {/* Quality Gate Filter */}
      <div>
        <label className="block text-[11px] font-bold text-gray-400 uppercase tracking-wider mb-2">
          Quality Gate Status
        </label>
        <div className="flex flex-col gap-1">
          {(['ALL', 'PASSED', 'FAILED'] as const).map((status) => (
            <button
              key={status}
              onClick={() => setQualityGateStatus(status as 'ALL' | QualityGateStatus)}
              className={cn(
                'flex items-center justify-between px-2.5 py-1.5 rounded text-xs font-semibold transition-colors text-left',
                qualityGateStatus === status
                  ? 'bg-sky-50 text-[#4b9fd5] border border-sky-200'
                  : 'text-gray-600 hover:bg-gray-50'
              )}
            >
              <span>{status === 'ALL' ? 'All Statuses' : status}</span>
              {qualityGateStatus === status && <Check className="w-3.5 h-3.5" />}
            </button>
          ))}
        </div>
      </div>

      {/* Reliability Rating */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Reliability Rating
        </label>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setReliabilityRating('ALL')}
            className={cn(
              'px-2 py-1 text-xs font-semibold rounded border',
              reliabilityRating === 'ALL'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
            )}
          >
            All
          </button>
          {ratings.map((r) => (
            <button
              key={r}
              onClick={() => setReliabilityRating(r)}
              className={cn(
                'w-7 h-7 text-xs font-bold rounded border transition-transform',
                reliabilityRating === r
                  ? 'bg-sky-600 text-white border-sky-600 scale-105'
                  : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Security Rating */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Security Rating
        </label>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setSecurityRating('ALL')}
            className={cn(
              'px-2 py-1 text-xs font-semibold rounded border',
              securityRating === 'ALL'
                ? 'bg-slate-900 text-white border-slate-900'
                : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
            )}
          >
            All
          </button>
          {ratings.map((r) => (
            <button
              key={r}
              onClick={() => setSecurityRating(r)}
              className={cn(
                'w-7 h-7 text-xs font-bold rounded border transition-transform',
                securityRating === r
                  ? 'bg-rose-600 text-white border-rose-600 scale-105'
                  : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50'
              )}
            >
              {r}
            </button>
          ))}
        </div>
      </div>

      {/* Language Filter */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Language
        </label>
        <select
          value={selectedLanguage}
          onChange={(e) => setSelectedLanguage(e.target.value)}
          className="w-full bg-slate-50 border border-slate-200 text-slate-800 text-xs rounded-lg px-2.5 py-2 font-medium focus:outline-none focus:ring-2 focus:ring-sky-500"
        >
          {languages.map((lang) => (
            <option key={lang} value={lang}>
              {lang === 'ALL' ? 'All Languages' : lang}
            </option>
          ))}
        </select>
      </div>

      {/* Tag Filter */}
      <div>
        <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">
          Tag
        </label>
        <div className="flex flex-wrap gap-1.5">
          {tags.map((tag) => (
            <button
              key={tag}
              onClick={() => setSelectedTag(tag)}
              className={cn(
                'px-2 py-1 rounded-md text-[11px] font-semibold transition-colors',
                selectedTag === tag
                  ? 'bg-slate-900 text-white'
                  : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              )}
            >
              {tag === 'ALL' ? 'All Tags' : `#${tag}`}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
