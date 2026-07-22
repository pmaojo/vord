import React from 'react';
import { MOCK_QUALITY_PROFILES } from '../../../testing/mock-data';
import { BookOpen, Star, Calendar, ArrowUpRight } from 'lucide-react';

export const QualityProfilesView: React.FC = () => {
  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-2">
            <BookOpen className="w-7 h-7 text-sky-600" />
            <span>Quality Profiles</span>
          </h1>
          <p className="text-sm text-slate-500 mt-1">
            Quality Profiles define the sets of active rules executed for each programming language during analysis.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {MOCK_QUALITY_PROFILES.map((profile) => (
          <div
            key={profile.key}
            className="bg-white rounded-2xl border border-slate-200 p-6 shadow-xs hover:shadow-md transition-all"
          >
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-bold uppercase tracking-wider text-sky-600 bg-sky-50 px-2.5 py-0.5 rounded-full border border-sky-200">
                  {profile.languageName}
                </span>
                <h3 className="text-xl font-bold text-slate-900 mt-2">{profile.name}</h3>
              </div>

              {profile.isDefault && (
                <span className="text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full flex items-center gap-1">
                  <Star className="w-3 h-3 fill-emerald-600" />
                  Default Profile
                </span>
              )}
            </div>

            <div className="mt-6 grid grid-cols-2 gap-4 bg-slate-50 p-4 rounded-xl border border-slate-100">
              <div>
                <div className="text-2xl font-black text-slate-900">{profile.activeRuleCount}</div>
                <div className="text-xs font-medium text-slate-500">Active Rules</div>
              </div>
              <div>
                <div className="text-2xl font-black text-amber-600">{profile.deprecatedRuleCount}</div>
                <div className="text-xs font-medium text-slate-500">Deprecated Rules</div>
              </div>
            </div>

            <div className="mt-4 pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500">
              <span className="flex items-center gap-1">
                <Calendar className="w-3.5 h-3.5" />
                Updated {profile.updatedAt}
              </span>

              <button
                onClick={() => alert(`Opening rules for ${profile.name}`)}
                className="text-sky-600 font-bold hover:underline flex items-center gap-1"
              >
                <span>View Rules</span>
                <ArrowUpRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
