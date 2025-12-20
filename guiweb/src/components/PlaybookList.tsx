import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Search,
  Filter,
  AlertTriangle,
  Calendar,
  Tag,
  Shield,
  ChevronDown,
  ChevronUp,
  Loader2,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import { usePlaybooks } from '../hooks/usePlaybooks';
import { cn, getSeverityBadgeColor, formatDate } from '../lib/utils';
import type { Playbook } from '../types/playbook';

type SortField = 'name' | 'severity' | 'created' | 'updated';
type SortDirection = 'asc' | 'desc';

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export default function PlaybookList() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedTag, setSelectedTag] = useState<string>('');
  const [sortField, setSortField] = useState<SortField>('updated');
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc');
  const [showFilters, setShowFilters] = useState(false);

  const { data: playbooks, isLoading, error, isError } = usePlaybooks();

  // Extract unique values for filters
  const { tactics, tags, severities } = useMemo(() => {
    if (!playbooks) return { tactics: [], tags: [], severities: [] };

    const tacticsSet = new Set<string>();
    const tagsSet = new Set<string>();
    const severitiesSet = new Set<string>();

    playbooks.forEach((pb) => {
      if (pb.mitre?.tactic) tacticsSet.add(pb.mitre.tactic);
      if (pb.tactic) tacticsSet.add(pb.tactic);
      pb.tags?.forEach((tag) => tagsSet.add(tag));
      severitiesSet.add(pb.severity);
    });

    return {
      tactics: Array.from(tacticsSet).sort(),
      tags: Array.from(tagsSet).sort(),
      severities: Array.from(severitiesSet).sort(
        (a, b) => severityOrder[a] - severityOrder[b]
      ),
    };
  }, [playbooks]);

  // Filter and sort playbooks
  const filteredPlaybooks = useMemo(() => {
    if (!playbooks) return [];

    let filtered = playbooks.filter((pb) => {
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          pb.name.toLowerCase().includes(query) ||
          pb.description.toLowerCase().includes(query) ||
          pb.mitre?.technique?.toLowerCase().includes(query) ||
          pb.mitre?.tactic?.toLowerCase().includes(query) ||
          pb.tags?.some((tag) => tag.toLowerCase().includes(query));

        if (!matchesSearch) return false;
      }

      // Tactic filter
      if (selectedTactic) {
        const matchesTactic =
          pb.mitre?.tactic === selectedTactic || pb.tactic === selectedTactic;
        if (!matchesTactic) return false;
      }

      // Severity filter
      if (selectedSeverity && pb.severity !== selectedSeverity) {
        return false;
      }

      // Tag filter
      if (selectedTag && !pb.tags?.includes(selectedTag)) {
        return false;
      }

      return true;
    });

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;

      switch (sortField) {
        case 'name':
          comparison = a.name.localeCompare(b.name);
          break;
        case 'severity':
          comparison = severityOrder[a.severity] - severityOrder[b.severity];
          break;
        case 'created':
          comparison = new Date(a.created).getTime() - new Date(b.created).getTime();
          break;
        case 'updated':
          comparison = new Date(a.updated).getTime() - new Date(b.updated).getTime();
          break;
      }

      return sortDirection === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [playbooks, searchQuery, selectedTactic, selectedSeverity, selectedTag, sortField, sortDirection]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null;
    return sortDirection === 'asc' ? (
      <ChevronUp size={16} className="inline" />
    ) : (
      <ChevronDown size={16} className="inline" />
    );
  };

  const clearFilters = () => {
    setSearchQuery('');
    setSelectedTactic('');
    setSelectedSeverity('');
    setSelectedTag('');
  };

  const hasActiveFilters = searchQuery || selectedTactic || selectedSeverity || selectedTag;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-10 w-10 animate-spin text-cyan-500" />
          <p className="text-gray-400">Loading playbooks...</p>
        </div>
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-6">
        <div className="flex items-start gap-3">
          <AlertCircle className="h-6 w-6 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="text-lg font-semibold text-red-400">Failed to load playbooks</h3>
            <p className="text-sm text-red-300/80 mt-1">
              {error instanceof Error ? error.message : 'An unexpected error occurred'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="mt-3 rounded-md bg-red-500/20 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-500/30 transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">Threat Hunting Playbooks</h1>
          <p className="text-gray-400 mt-1">
            {filteredPlaybooks.length} of {playbooks?.length || 0} playbooks
          </p>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="space-y-4">
        {/* Search Bar */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search playbooks by name, description, technique, or tag..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-lg border border-gray-800 bg-gray-900 pl-10 pr-4 py-3 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
          />
        </div>

        {/* Filter Toggle */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFilters(!showFilters)}
            className={cn(
              'flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-colors',
              showFilters
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            )}
          >
            <Filter size={16} />
            Filters
            {hasActiveFilters && (
              <span className="rounded-full bg-cyan-500 px-2 py-0.5 text-xs text-white">
                {[searchQuery, selectedTactic, selectedSeverity, selectedTag].filter(Boolean).length}
              </span>
            )}
          </button>

          {hasActiveFilters && (
            <button
              onClick={clearFilters}
              className="text-sm text-gray-400 hover:text-gray-200 transition-colors"
            >
              Clear all
            </button>
          )}
        </div>

        {/* Filter Options */}
        {showFilters && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 p-4 rounded-lg border border-gray-800 bg-gray-900/50">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Tactic
              </label>
              <select
                value={selectedTactic}
                onChange={(e) => setSelectedTactic(e.target.value)}
                className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
              >
                <option value="">All tactics</option>
                {tactics.map((tactic) => (
                  <option key={tactic} value={tactic}>
                    {tactic}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Severity
              </label>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
              >
                <option value="">All severities</option>
                {severities.map((severity) => (
                  <option key={severity} value={severity}>
                    {severity.charAt(0).toUpperCase() + severity.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Tag
              </label>
              <select
                value={selectedTag}
                onChange={(e) => setSelectedTag(e.target.value)}
                className="w-full rounded-lg border border-gray-800 bg-gray-900 px-3 py-2 text-gray-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
              >
                <option value="">All tags</option>
                {tags.map((tag) => (
                  <option key={tag} value={tag}>
                    {tag}
                  </option>
                ))}
              </select>
            </div>
          </div>
        )}
      </div>

      {/* Playbooks Table */}
      <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-gray-800 bg-gray-900/50">
              <tr>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => handleSort('name')}
                    className="flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-gray-400 hover:text-gray-200 transition-colors"
                  >
                    Name
                    <SortIcon field="name" />
                  </button>
                </th>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => handleSort('severity')}
                    className="flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-gray-400 hover:text-gray-200 transition-colors"
                  >
                    Severity
                    <SortIcon field="severity" />
                  </button>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                  MITRE ATT&CK
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                  Tags
                </th>
                <th className="px-6 py-3 text-left">
                  <button
                    onClick={() => handleSort('updated')}
                    className="flex items-center gap-1 text-xs font-medium uppercase tracking-wider text-gray-400 hover:text-gray-200 transition-colors"
                  >
                    Updated
                    <SortIcon field="updated" />
                  </button>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filteredPlaybooks.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-6 py-12 text-center">
                    <div className="flex flex-col items-center gap-2">
                      <AlertTriangle className="h-10 w-10 text-gray-600" />
                      <p className="text-gray-400">No playbooks found</p>
                      {hasActiveFilters && (
                        <button
                          onClick={clearFilters}
                          className="text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
                        >
                          Clear filters
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filteredPlaybooks.map((playbook) => (
                  <tr
                    key={playbook.id}
                    className="group hover:bg-gray-800/50 transition-colors"
                  >
                    <td className="px-6 py-4">
                      <Link
                        to={`/playbook/${playbook.id}`}
                        className="flex items-start gap-3"
                      >
                        <Shield className="h-5 w-5 text-cyan-500 flex-shrink-0 mt-0.5 group-hover:text-cyan-400 transition-colors" />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <p className="font-medium text-gray-100 group-hover:text-cyan-400 transition-colors">
                              {playbook.name}
                            </p>
                            <ExternalLink className="h-4 w-4 text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity" />
                          </div>
                          <p className="text-sm text-gray-400 mt-1 line-clamp-2">
                            {playbook.description}
                          </p>
                        </div>
                      </Link>
                    </td>
                    <td className="px-6 py-4">
                      <span
                        className={cn(
                          'inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold',
                          getSeverityBadgeColor(playbook.severity)
                        )}
                      >
                        <AlertTriangle size={12} />
                        {playbook.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="space-y-1">
                        {playbook.mitre?.technique && (
                          <div className="flex items-center gap-1.5 text-sm text-gray-300">
                            <Shield size={14} className="text-gray-500" />
                            <code className="text-xs bg-gray-800 px-1.5 py-0.5 rounded">
                              {playbook.mitre.technique}
                            </code>
                          </div>
                        )}
                        {(playbook.mitre?.tactic || playbook.tactic) && (
                          <p className="text-xs text-gray-500">
                            {playbook.mitre?.tactic || playbook.tactic}
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex flex-wrap gap-1">
                        {playbook.tags?.slice(0, 3).map((tag) => (
                          <span
                            key={tag}
                            className="inline-flex items-center gap-1 rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400"
                          >
                            <Tag size={10} />
                            {tag}
                          </span>
                        ))}
                        {playbook.tags && playbook.tags.length > 3 && (
                          <span className="inline-flex items-center rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-500">
                            +{playbook.tags.length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-1.5 text-sm text-gray-400">
                        <Calendar size={14} className="text-gray-500" />
                        {formatDate(playbook.updated)}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
