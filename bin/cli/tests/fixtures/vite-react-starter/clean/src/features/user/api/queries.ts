import { useQuery } from '@tanstack/react-query';

import { httpClient } from '../../../infra/http/client';

async function fetchUser(id: string) {
  const response = await httpClient.get(`/users/${id}`);
  return response.data;
}

export function useUser(id: string) {
  return useQuery(['user', id], () => fetchUser(id));
}
