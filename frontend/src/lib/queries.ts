//! Shared react-query hooks so components that need the same server data
//! (rules catalog, projects, system info) hit the network once and share a
//! cache instead of each re-fetching independently.

import { useQuery } from '@tanstack/react-query';
import {
  fetchRulesFromApi,
  fetchProjectsFromApi,
  fetchIssuesFromApi,
  fetchSystemInfo,
  fetchAuditLog,
  fetchQueueStatus,
  fetchProjectActivity,
} from './api';

export function useRules() {
  return useQuery({ queryKey: ['rules'], queryFn: fetchRulesFromApi, staleTime: 1000 * 60 * 10 });
}

export function useProjects() {
  return useQuery({ queryKey: ['projects'], queryFn: fetchProjectsFromApi });
}

export function useIssuesForSearch(enabled: boolean) {
  return useQuery({
    queryKey: ['issues', 'search'],
    queryFn: () => fetchIssuesFromApi({ pageSize: 200 }),
    enabled,
  });
}

export function useSystemInfo() {
  return useQuery({ queryKey: ['system-info'], queryFn: fetchSystemInfo, refetchInterval: 30_000 });
}

export function useAuditLog(entityType?: string) {
  return useQuery({
    queryKey: ['audit-log', entityType ?? 'all'],
    queryFn: () => fetchAuditLog({ entityType, pageSize: 100 }),
  });
}

export function useQueueStatus() {
  return useQuery({
    queryKey: ['queue-status'],
    queryFn: fetchQueueStatus,
    refetchInterval: 15_000,
    retry: false,
  });
}

export function useProjectActivity(projectKey: string) {
  return useQuery({
    queryKey: ['project-activity', projectKey],
    queryFn: () => fetchProjectActivity(projectKey, { pageSize: 20 }),
    enabled: !!projectKey,
    refetchInterval: 15_000,
  });
}
