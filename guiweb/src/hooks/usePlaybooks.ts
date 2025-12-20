import { useQuery } from '@tanstack/react-query';
import { getPlaybooks, getPlaybook, searchPlaybooks } from '../services/api';
import type { SearchFilters } from '../types/playbook';

export function usePlaybooks(limit?: number, offset?: number) {
  return useQuery({
    queryKey: ['playbooks', limit, offset],
    queryFn: () => getPlaybooks(limit, offset),
    staleTime: 5 * 60 * 1000, // 5 minutes
  });
}

export function usePlaybook(id: string) {
  return useQuery({
    queryKey: ['playbook', id],
    queryFn: () => getPlaybook(id),
    enabled: !!id,
    staleTime: 10 * 60 * 1000, // 10 minutes
  });
}

export function useSearchPlaybooks(filters: SearchFilters) {
  return useQuery({
    queryKey: ['search', filters],
    queryFn: () => searchPlaybooks(filters),
    enabled: Object.keys(filters).some(key => filters[key as keyof SearchFilters]),
    staleTime: 2 * 60 * 1000, // 2 minutes
  });
}
