import React from 'react';
import { MOCK_PROJECTS } from '../../../testing/mock-data';
import { useProjectsStore } from '../stores/useProjectsStore';
import { ProjectCard } from './ProjectCard';
import { ProjectRow } from './ProjectRow';
import { ProjectFilters } from './ProjectFilters';
import { Search, LayoutGrid, List, ArrowUpDown } from 'lucide-react';

export const ProjectsList: React.FC = () => {
  const {
    searchQuery,
    setSearchQuery,
    qualityGateStatus,
    reliabilityRating,
    securityRating,
    selectedLanguage,
    selectedTag,
    sortBy,
    setSortBy,
    viewMode,
    setViewMode,
  } = useProjectsStore();

  const filteredProjects = MOCK_PROJECTS.filter((project) => {
    if (
      searchQuery &&
      !project.name.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !project.key.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    if (qualityGateStatus !== 'ALL' && project.qualityGateStatus !== qualityGateStatus) {
      return false;
    }
    if (reliabilityRating !== 'ALL' && project.metrics.bugsRating !== reliabilityRating) {
      return false;
    }
    if (securityRating !== 'ALL' && project.metrics.vulnerabilitiesRating !== securityRating) {
      return false;
    }
    if (selectedLanguage !== 'ALL' && project.language !== selectedLanguage) {
      return false;
    }
    if (selectedTag !== 'ALL' && !project.tags.includes(selectedTag)) {
      return false;
    }
    return true;
  }).sort((a, b) => {
    if (sortBy === 'name') return a.name.localeCompare(b.name);
    if (sortBy === 'bugs') return b.metrics.bugs - a.metrics.bugs;
    if (sortBy === 'coverage') return b.metrics.coverage - a.metrics.coverage;
    if (sortBy === 'ncloc') return b.metrics.ncloc - a.metrics.ncloc;
    // default lastAnalysisDate
    return new Date(b.lastAnalysisDate).getTime() - new Date(a.lastAnalysisDate).getTime();
  });

  return (
    <div className="max-w-7xl mx-auto px-4 py-8">
      {/* Portfolio Title & Controls */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 bg-white border border-gray-200 p-4 rounded shadow-2xs">
        <div>
          <h1 className="text-xl font-light text-[#233445]">
            Projects <span className="text-gray-400 font-normal text-sm ml-2">{filteredProjects.length} Projects shown</span>
          </h1>
          <p className="text-xs text-gray-500 mt-0.5">
            Analyzing codebases across enterprise repositories
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* Search bar */}
          <div className="relative w-60 sm:w-72">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search projects..."
              className="w-full bg-[#f3f6f9] border border-gray-300 rounded pl-8 pr-3 py-1.5 text-xs text-[#233445] placeholder:text-gray-400 focus:outline-none focus:ring-1 focus:ring-[#4b9fd5] font-medium"
            />
          </div>

          {/* Sort By Dropdown */}
          <div className="flex items-center gap-1 bg-white border border-gray-300 rounded px-2.5 py-1 text-xs text-[#233445] font-medium">
            <ArrowUpDown className="w-3.5 h-3.5 text-gray-400" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="bg-transparent border-none outline-none font-medium cursor-pointer"
            >
              <option value="lastAnalysisDate">Last Analysis</option>
              <option value="name">Sorted by Name</option>
              <option value="bugs">Bugs Count</option>
              <option value="coverage">Coverage %</option>
              <option value="ncloc">Lines of Code</option>
            </select>
          </div>

          {/* View Mode Toggle */}
          <div className="flex gap-px bg-gray-200 border border-gray-200 rounded p-0.5">
            <button
              onClick={() => setViewMode('card')}
              className={`px-2 py-1 text-[10px] font-bold uppercase transition-colors ${
                viewMode === 'card' ? 'bg-white text-[#233445] shadow-xs' : 'text-gray-500 hover:text-gray-900'
              }`}
              title="Grid Cards"
            >
              CARDS
            </button>
            <button
              onClick={() => setViewMode('list')}
              className={`px-2 py-1 text-[10px] font-bold uppercase transition-colors ${
                viewMode === 'list' ? 'bg-white text-[#233445] shadow-xs' : 'text-gray-500 hover:text-gray-900'
              }`}
              title="Data Grid List"
            >
              LIST
            </button>
          </div>
        </div>
      </div>

      {/* Main Grid with Sidebar Filter */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Sidebar Filters */}
        <div className="lg:col-span-1">
          <ProjectFilters />
        </div>

        {/* Results Area */}
        <div className="lg:col-span-3">
          {filteredProjects.length === 0 ? (
            <div className="bg-white rounded-xl border border-slate-200 p-12 text-center text-slate-500 shadow-xs">
              <p className="text-base font-semibold text-slate-800">No projects match the selected filters.</p>
              <p className="text-xs text-slate-500 mt-1">Try resetting filters or adjusting search keywords.</p>
            </div>
          ) : viewMode === 'card' ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {filteredProjects.map((project) => (
                <ProjectCard key={project.key} project={project} />
              ))}
            </div>
          ) : (
            <div className="bg-white rounded-xl border border-slate-200 shadow-xs overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200 text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                    <th className="py-3 px-4">Project</th>
                    <th className="py-3 px-4 text-center">Quality Gate</th>
                    <th className="py-3 px-4 text-center">Bugs</th>
                    <th className="py-3 px-4 text-center">Vulnerabilities</th>
                    <th className="py-3 px-4 text-center">Code Smells</th>
                    <th className="py-3 px-4 text-center">Coverage</th>
                    <th className="py-3 px-4 text-center">Duplication</th>
                    <th className="py-3 px-4 text-center">LOC</th>
                    <th className="py-3 px-4 text-right">Last Analysis</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProjects.map((project) => (
                    <ProjectRow key={project.key} project={project} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
