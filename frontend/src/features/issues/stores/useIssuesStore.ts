import { create } from 'zustand';
import { IssueType, IssueSeverity, IssueStatus } from '../../../types';

interface IssuesFilterState {
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  selectedTypes: IssueType[];
  toggleType: (type: IssueType) => void;
  selectedSeverities: IssueSeverity[];
  toggleSeverity: (severity: IssueSeverity) => void;
  selectedStatuses: IssueStatus[];
  toggleStatus: (status: IssueStatus) => void;
  assigneeFilter: string;
  setAssigneeFilter: (a: string) => void;
  ruleFilter: string;
  setRuleFilter: (r: string) => void;
  selectedIssueIds: string[];
  toggleIssueSelection: (id: string) => void;
  selectAllIssues: (ids: string[]) => void;
  clearIssueSelections: () => void;
  resetFilters: () => void;
}

export const useIssuesStore = create<IssuesFilterState>((set) => ({
  searchQuery: '',
  setSearchQuery: (q) => set({ searchQuery: q }),
  selectedTypes: [],
  toggleType: (type) =>
    set((state) => ({
      selectedTypes: state.selectedTypes.includes(type)
        ? state.selectedTypes.filter((t) => t !== type)
        : [...state.selectedTypes, type],
    })),
  selectedSeverities: [],
  toggleSeverity: (severity) =>
    set((state) => ({
      selectedSeverities: state.selectedSeverities.includes(severity)
        ? state.selectedSeverities.filter((s) => s !== severity)
        : [...state.selectedSeverities, severity],
    })),
  selectedStatuses: [],
  toggleStatus: (status) =>
    set((state) => ({
      selectedStatuses: state.selectedStatuses.includes(status)
        ? state.selectedStatuses.filter((s) => s !== status)
        : [...state.selectedStatuses, status],
    })),
  assigneeFilter: 'ALL',
  setAssigneeFilter: (a) => set({ assigneeFilter: a }),
  ruleFilter: '',
  setRuleFilter: (r) => set({ ruleFilter: r }),
  selectedIssueIds: [],
  toggleIssueSelection: (id) =>
    set((state) => ({
      selectedIssueIds: state.selectedIssueIds.includes(id)
        ? state.selectedIssueIds.filter((i) => i !== id)
        : [...state.selectedIssueIds, id],
    })),
  selectAllIssues: (ids) => set({ selectedIssueIds: ids }),
  clearIssueSelections: () => set({ selectedIssueIds: [] }),
  resetFilters: () =>
    set({
      searchQuery: '',
      selectedTypes: [],
      selectedSeverities: [],
      selectedStatuses: [],
      assigneeFilter: 'ALL',
      ruleFilter: '',
      selectedIssueIds: [],
    }),
}));
