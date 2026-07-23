import { create } from 'zustand';

interface GlobalState {
  isSearchOpen: boolean;
  setSearchOpen: (open: boolean) => void;
  activeProjectKey: string | null;
  setActiveProjectKey: (key: string | null) => void;
  user: {
    name: string;
    email: string;
    avatar: string;
    role: string;
  };
}

export const useGlobalStore = create<GlobalState>((set) => ({
  isSearchOpen: false,
  setSearchOpen: (open) => set({ isSearchOpen: open }),
  activeProjectKey: null,
  setActiveProjectKey: (key) => set({ activeProjectKey: key }),
  user: {
    name: 'Administrator',
    email: 'admin@yunq.enterprise',
    avatar: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=80',
    role: 'System Administrator',
  },
}));
