import { create } from 'zustand';
import { QualityGateStatus, Rating } from '../../../types';

interface ProjectsFilterState {
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  qualityGateStatus: 'ALL' | QualityGateStatus;
  setQualityGateStatus: (s: 'ALL' | QualityGateStatus) => void;
  reliabilityRating: Rating | 'ALL';
  setReliabilityRating: (r: Rating | 'ALL') => void;
  securityRating: Rating | 'ALL';
  setSecurityRating: (r: Rating | 'ALL') => void;
  selectedLanguage: string;
  setSelectedLanguage: (lang: string) => void;
  selectedTag: string;
  setSelectedTag: (tag: string) => void;
  sortBy: 'name' | 'lastAnalysisDate' | 'bugs' | 'coverage' | 'ncloc';
  setSortBy: (sort: 'name' | 'lastAnalysisDate' | 'bugs' | 'coverage' | 'ncloc') => void;
  viewMode: 'list' | 'card';
  setViewMode: (mode: 'list' | 'card') => void;
  resetFilters: () => void;
}

export const useProjectsStore = create<ProjectsFilterState>((set) => ({
  searchQuery: '',
  setSearchQuery: (q) => set({ searchQuery: q }),
  qualityGateStatus: 'ALL',
  setQualityGateStatus: (s) => set({ qualityGateStatus: s }),
  reliabilityRating: 'ALL',
  setReliabilityRating: (r) => set({ reliabilityRating: r }),
  securityRating: 'ALL',
  setSecurityRating: (r) => set({ securityRating: r }),
  selectedLanguage: 'ALL',
  setSelectedLanguage: (lang) => set({ selectedLanguage: lang }),
  selectedTag: 'ALL',
  setSelectedTag: (tag) => set({ selectedTag: tag }),
  sortBy: 'lastAnalysisDate',
  setSortBy: (sort) => set({ sortBy: sort }),
  viewMode: 'card',
  setViewMode: (mode) => set({ viewMode: mode }),
  resetFilters: () =>
    set({
      searchQuery: '',
      qualityGateStatus: 'ALL',
      reliabilityRating: 'ALL',
      securityRating: 'ALL',
      selectedLanguage: 'ALL',
      selectedTag: 'ALL',
      sortBy: 'lastAnalysisDate',
    }),
}));
