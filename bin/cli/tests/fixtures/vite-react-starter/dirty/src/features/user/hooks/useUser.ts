import { useQuery } from '@tanstack/react-query';

export function useUser(id: string) {
  return useQuery(['user', id], () => fetch(`/api/users/${id}`).then((r) => r.json()));
}
