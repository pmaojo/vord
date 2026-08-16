import { create } from 'zustand';

const useStore = create(() => ({ count: 0 }));

export function UserCard() {
  return (
    <div className="flex space-x-4">
      <span className="h-4 w-4">{useStore.getState().count}</span>
    </div>
  );
}
