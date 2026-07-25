import { create } from 'zustand';

interface GlobalState {
  isSearchOpen: boolean;
  setSearchOpen: (open: boolean) => void;
  activeProjectKey: string | null;
  setActiveProjectKey: (key: string | null) => void;
}

export const useGlobalStore = create<GlobalState>((set) => ({
  isSearchOpen: false,
  setSearchOpen: (open) => set({ isSearchOpen: open }),
  activeProjectKey: null,
  setActiveProjectKey: (key) => set({ activeProjectKey: key }),
}));
