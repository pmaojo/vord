import { create } from 'zustand';

const useStore = create(() => ({ count: 0 }));

export function UserCard() {
  return (
    <div className="flex space-x-4">
      <span>{useStore.getState().count}</span>
    </div>
  );
}
