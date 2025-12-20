import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  ExternalLink,
  Loader2,
  AlertCircle,
  Target,
  TrendingUp,
  Plus,
  XCircle,
  Info,
} from 'lucide-react';
import { usePlaybooks } from '../hooks/usePlaybooks';
import { cn } from '../lib/utils';

// MITRE ATT&CK Enterprise Tactics (in order)
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', short: 'Recon', color: 'from-purple-600 to-purple-700' },
  { id: 'TA0042', name: 'Resource Development', short: 'Resource', color: 'from-indigo-600 to-indigo-700' },
  { id: 'TA0001', name: 'Initial Access', short: 'Initial', color: 'from-blue-600 to-blue-700' },
  { id: 'TA0002', name: 'Execution', short: 'Exec', color: 'from-cyan-600 to-cyan-700' },
  { id: 'TA0003', name: 'Persistence', short: 'Persist', color: 'from-teal-600 to-teal-700' },
  { id: 'TA0004', name: 'Privilege Escalation', short: 'PrivEsc', color: 'from-green-600 to-green-700' },
  { id: 'TA0005', name: 'Defense Evasion', short: 'Defense', color: 'from-lime-600 to-lime-700' },
  { id: 'TA0006', name: 'Credential Access', short: 'Creds', color: 'from-yellow-600 to-yellow-700' },
  { id: 'TA0007', name: 'Discovery', short: 'Discover', color: 'from-orange-600 to-orange-700' },
  { id: 'TA0008', name: 'Lateral Movement', short: 'Lateral', color: 'from-red-600 to-red-700' },
  { id: 'TA0009', name: 'Collection', short: 'Collect', color: 'from-pink-600 to-pink-700' },
  { id: 'TA0011', name: 'Command and Control', short: 'C2', color: 'from-fuchsia-600 to-fuchsia-700' },
  { id: 'TA0010', name: 'Exfiltration', short: 'Exfil', color: 'from-rose-600 to-rose-700' },
  { id: 'TA0040', name: 'Impact', short: 'Impact', color: 'from-red-700 to-red-800' },
];

type ViewMode = 'matrix' | 'list';

export default function MitreMatrixV2() {
  const [viewMode, setViewMode] = useState<ViewMode>('matrix');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);
  const [showGapsOnly, setShowGapsOnly] = useState(false);

  const { data: playbooks, isLoading, isError, error } = usePlaybooks();

  // Helper to get technique from playbook (supports both formats)
  const getTechnique = (playbook: { mitre?: { technique?: string }; technique?: string }): string | undefined => {
    return playbook.mitre?.technique || playbook.technique;
  };

  // Helper to get tactic from playbook (supports both formats)
  const getTactic = (playbook: { mitre?: { tactic?: string }; tactic?: string }): string | undefined => {
    return playbook.mitre?.tactic || playbook.tactic;
  };

  // Build technique-to-playbooks mapping with count
  const techniqueMap = useMemo(() => {
    if (!playbooks) return new Map<string, typeof playbooks>();

    const map = new Map<string, typeof playbooks>();

    playbooks.forEach((playbook) => {
      const techniqueId = getTechnique(playbook);
      if (techniqueId) {
        if (!map.has(techniqueId)) {
          map.set(techniqueId, []);
        }
        map.get(techniqueId)!.push(playbook);
      }
    });

    return map;
  }, [playbooks]);

  // Helper to normalize tactic name
  const normalizeTactic = (tactic: string): string => {
    // Convert kebab-case to Title Case
    return tactic
      .split('-')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  };

  // Build tactic-to-techniques mapping with coverage stats
  const tacticStats = useMemo(() => {
    if (!playbooks) return new Map();

    const stats = new Map<string, { techniques: Set<string>; playbooks: number; coverage: number }>();

    playbooks.forEach((playbook) => {
      const rawTactic = getTactic(playbook);
      const technique = getTechnique(playbook);

      if (rawTactic && technique) {
        // Normalize tactic name (kebab-case to Title Case)
        const tactic = normalizeTactic(rawTactic);

        if (!stats.has(tactic)) {
          stats.set(tactic, { techniques: new Set(), playbooks: 0, coverage: 0 });
        }
        const stat = stats.get(tactic)!;
        stat.techniques.add(technique);
        stat.playbooks++;
      }
    });

    // Calculate coverage percentage (assuming ~14 avg techniques per tactic)
    stats.forEach((stat) => {
      stat.coverage = Math.min(100, Math.round((stat.techniques.size / 14) * 100));
    });

    return stats;
  }, [playbooks]);

  // Get coverage color based on count
  const getCoverageColor = (count: number): string => {
    if (count === 0) return 'bg-gray-800 border-gray-700';
    if (count === 1) return 'bg-blue-900/50 border-blue-700/50';
    if (count === 2) return 'bg-cyan-800/60 border-cyan-600/60';
    if (count === 3) return 'bg-green-700/70 border-green-500/70';
    return 'bg-orange-600/80 border-orange-400/80'; // 4+
  };


  // Get techniques for selected tactic
  const techniquesForTactic = useMemo(() => {
    if (!selectedTactic || !playbooks) return [];

    const techniques = new Set<string>();
    playbooks.forEach((pb) => {
      const rawTactic = getTactic(pb);
      const technique = getTechnique(pb);
      if (rawTactic) {
        const tactic = normalizeTactic(rawTactic);
        if (tactic === selectedTactic && technique) {
          techniques.add(technique);
        }
      }
    });

    return Array.from(techniques).sort();
  }, [selectedTactic, playbooks]);

  // Gap analysis - techniques without playbooks
  const gapAnalysis = useMemo(() => {
    if (!playbooks) return { totalTechniques: 0, gapPercentage: 0 };

    const totalTechniques = techniqueMap.size;
    // Assuming ~193 total techniques in MITRE ATT&CK Enterprise
    const totalPossible = 193;
    const gapPercentage = Math.round(((totalPossible - totalTechniques) / totalPossible) * 100);

    return {
      totalTechniques: totalPossible,
      gapPercentage,
    };
  }, [techniqueMap, playbooks]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-10 w-10 animate-spin text-cyan-500" />
          <p className="text-gray-400">Loading MITRE ATT&CK Matrix...</p>
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
            <h3 className="text-lg font-semibold text-red-400">Failed to load MITRE Matrix</h3>
            <p className="text-sm text-red-300/80 mt-1">
              {error instanceof Error ? error.message : 'An unexpected error occurred'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">MITRE ATT&CK Matrix</h1>
          <p className="text-gray-400 mt-1">Interactive coverage heatmap and gap analysis</p>
        </div>
        <div className="flex items-center gap-3">
          <a
            href="https://attack.mitre.org/"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 rounded-lg bg-gray-800 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-700 transition-colors"
          >
            <ExternalLink size={16} />
            MITRE ATT&CK
          </a>
        </div>
      </div>

      {/* Coverage Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/10 p-3">
              <Target className="h-6 w-6 text-cyan-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100">{techniqueMap.size}</p>
              <p className="text-sm text-gray-400">Techniques Covered</p>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-blue-500/10 p-3">
              <Shield className="h-6 w-6 text-blue-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100">{playbooks?.length || 0}</p>
              <p className="text-sm text-gray-400">Total Playbooks</p>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-green-500/10 p-3">
              <TrendingUp className="h-6 w-6 text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100">
                {Math.round((techniqueMap.size / 193) * 100)}%
              </p>
              <p className="text-sm text-gray-400">Coverage Rate</p>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-orange-500/10 p-3">
              <XCircle className="h-6 w-6 text-orange-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100">{gapAnalysis.gapPercentage}%</p>
              <p className="text-sm text-gray-400">Coverage Gaps</p>
            </div>
          </div>
        </div>
      </div>

      {/* View Controls */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 rounded-lg border border-gray-800 bg-gray-900 p-1">
          <button
            onClick={() => setViewMode('matrix')}
            className={cn(
              'rounded-md px-4 py-2 text-sm font-medium transition-colors',
              viewMode === 'matrix'
                ? 'bg-cyan-500/10 text-cyan-400'
                : 'text-gray-400 hover:text-gray-200'
            )}
          >
            Matrix View
          </button>
          <button
            onClick={() => setViewMode('list')}
            className={cn(
              'rounded-md px-4 py-2 text-sm font-medium transition-colors',
              viewMode === 'list'
                ? 'bg-cyan-500/10 text-cyan-400'
                : 'text-gray-400 hover:text-gray-200'
            )}
          >
            List View
          </button>
        </div>

        <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
          <input
            type="checkbox"
            checked={showGapsOnly}
            onChange={(e) => setShowGapsOnly(e.target.checked)}
            className="rounded border-gray-700 bg-gray-800 text-cyan-500 focus:ring-cyan-500 focus:ring-offset-gray-900"
          />
          Show gaps only
        </label>
      </div>

      {/* Legend */}
      <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-4">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-sm text-blue-300 mb-3">
              Heat intensity represents playbook coverage per technique:
            </p>
            <div className="flex items-center gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded bg-gray-800 border border-gray-700" />
                <span className="text-xs text-gray-400">No coverage (0)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded bg-blue-900/50 border border-blue-700/50" />
                <span className="text-xs text-gray-400">Low (1)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded bg-cyan-800/60 border border-cyan-600/60" />
                <span className="text-xs text-gray-400">Medium (2)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded bg-green-700/70 border border-green-500/70" />
                <span className="text-xs text-gray-400">Good (3)</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded bg-orange-600/80 border border-orange-400/80" />
                <span className="text-xs text-gray-400">Excellent (4+)</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {viewMode === 'matrix' ? (
        /* Matrix View */
        <div className="rounded-lg border border-gray-800 bg-gray-900 overflow-hidden">
          <div className="overflow-x-auto">
            <div className="inline-grid gap-2 p-6 min-w-max" style={{ gridTemplateColumns: `repeat(${MITRE_TACTICS.length}, minmax(140px, 1fr))` }}>
              {/* Tactic Headers */}
              {MITRE_TACTICS.map((tactic) => {
                const stats = tacticStats.get(tactic.name);
                const techniqueCount = stats?.techniques.size || 0;
                const playbookCount = stats?.playbooks || 0;
                const coverage = stats?.coverage || 0;

                return (
                  <button
                    key={tactic.id}
                    onClick={() => setSelectedTactic(selectedTactic === tactic.name ? null : tactic.name)}
                    className={cn(
                      'rounded-lg p-4 transition-all border-2',
                      selectedTactic === tactic.name
                        ? 'border-cyan-500 bg-cyan-500/10'
                        : 'border-gray-800 bg-gray-950 hover:border-gray-700 hover:bg-gray-800'
                    )}
                  >
                    <div className="flex flex-col items-center gap-2">
                      <div className={cn('rounded-lg bg-gradient-to-br p-2', tactic.color)}>
                        <Shield className="h-4 w-4 text-white" />
                      </div>
                      <h3 className="font-semibold text-gray-100 text-sm text-center leading-tight">
                        {tactic.short}
                      </h3>
                      <div className="w-full space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-gray-500">Coverage</span>
                          <span className="text-cyan-400 font-medium">{coverage}%</span>
                        </div>
                        <div className="h-1.5 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all"
                            style={{ width: `${coverage}%` }}
                          />
                        </div>
                      </div>
                      <div className="flex items-center justify-between w-full text-xs">
                        <div className="flex items-center gap-1 text-gray-400">
                          <Target size={12} />
                          {techniqueCount}
                        </div>
                        <div className="flex items-center gap-1 text-gray-400">
                          <Shield size={12} />
                          {playbookCount}
                        </div>
                      </div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Technique Details for Selected Tactic */}
          {selectedTactic && (
            <div className="border-t border-gray-800 bg-gray-950 p-6">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-lg font-semibold text-gray-100">
                  Techniques for {selectedTactic}
                </h3>
                <Link
                  to="/playbook/new"
                  className="flex items-center gap-2 rounded-lg bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                >
                  <Plus size={16} />
                  Add Playbook
                </Link>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                {techniquesForTactic.map((techniqueId) => {
                  const playbooksForTechnique = techniqueMap.get(techniqueId) || [];
                  const count = playbooksForTechnique.length;

                  return (
                    <button
                      key={techniqueId}
                      onClick={() => setSelectedTechnique(selectedTechnique === techniqueId ? null : techniqueId)}
                      className={cn(
                        'rounded-lg p-4 border-2 transition-all text-left',
                        selectedTechnique === techniqueId
                          ? 'border-cyan-500'
                          : 'border-transparent',
                        getCoverageColor(count),
                        'hover:scale-105'
                      )}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <code className="text-sm font-semibold text-cyan-400">{techniqueId}</code>
                        <span className={cn(
                          'rounded-full px-2 py-0.5 text-xs font-bold',
                          count === 0 ? 'bg-gray-700 text-gray-400' :
                          count === 1 ? 'bg-blue-500/20 text-blue-400' :
                          count === 2 ? 'bg-cyan-500/20 text-cyan-400' :
                          count === 3 ? 'bg-green-500/20 text-green-400' :
                          'bg-orange-500/20 text-orange-400'
                        )}>
                          {count}
                        </span>
                      </div>
                      <p className="text-xs text-gray-400">
                        {count} playbook{count !== 1 ? 's' : ''}
                      </p>
                    </button>
                  );
                })}
              </div>

              {/* Playbooks for Selected Technique */}
              {selectedTechnique && (
                <div className="mt-6 space-y-2">
                  <h4 className="text-md font-semibold text-gray-100 mb-3">
                    Playbooks for {selectedTechnique}
                  </h4>
                  {(techniqueMap.get(selectedTechnique) || []).map((playbook) => (
                    <Link
                      key={playbook.id}
                      to={`/playbook/${playbook.id}`}
                      className="block rounded-lg border border-gray-800 bg-gray-900 p-3 hover:border-cyan-500/50 hover:bg-gray-800/50 transition-all group"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <p className="font-medium text-gray-100 truncate group-hover:text-cyan-400 transition-colors">
                            {playbook.name}
                          </p>
                          <p className="text-sm text-gray-400 line-clamp-2 mt-1">
                            {playbook.description}
                          </p>
                        </div>
                        <ExternalLink className="h-4 w-4 text-gray-600 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        /* List View */
        <div className="space-y-2">
          {MITRE_TACTICS.map((tactic) => {
            const stats = tacticStats.get(tactic.name);
            const techniqueCount = stats?.techniques.size || 0;
            const playbookCount = stats?.playbooks || 0;

            return (
              <div key={tactic.id} className="rounded-lg border border-gray-800 bg-gray-900">
                <button
                  onClick={() => setSelectedTactic(selectedTactic === tactic.name ? null : tactic.name)}
                  className="flex w-full items-center justify-between px-6 py-4 text-left hover:bg-gray-800/50 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    <div className={cn('rounded-lg bg-gradient-to-br p-3', tactic.color)}>
                      <Shield className="h-5 w-5 text-white" />
                    </div>
                    <div>
                      <h3 className="font-semibold text-gray-100">{tactic.name}</h3>
                      <p className="text-sm text-gray-500">{tactic.id}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <p className="text-sm text-gray-400">{techniqueCount} techniques</p>
                      <p className="text-sm text-cyan-400 font-medium">{playbookCount} playbooks</p>
                    </div>
                    <Target className={cn(
                      'h-5 w-5 transition-transform',
                      selectedTactic === tactic.name ? 'rotate-90' : ''
                    )} />
                  </div>
                </button>

                {selectedTactic === tactic.name && (
                  <div className="border-t border-gray-800 p-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                      {techniquesForTactic.map((techniqueId) => {
                        const playbooksForTechnique = techniqueMap.get(techniqueId) || [];
                        const count = playbooksForTechnique.length;

                        return (
                          <button
                            key={techniqueId}
                            onClick={() => setSelectedTechnique(selectedTechnique === techniqueId ? null : techniqueId)}
                            className={cn(
                              'rounded-lg p-3 border-2 transition-all text-left',
                              selectedTechnique === techniqueId
                                ? 'border-cyan-500'
                                : 'border-transparent',
                              getCoverageColor(count)
                            )}
                          >
                            <div className="flex items-center justify-between">
                              <code className="text-sm font-semibold text-cyan-400">{techniqueId}</code>
                              <span className="rounded-full bg-gray-800 px-2 py-0.5 text-xs font-semibold text-gray-400">
                                {count}
                              </span>
                            </div>
                          </button>
                        );
                      })}
                    </div>

                    {selectedTechnique && (
                      <div className="mt-4 space-y-2">
                        {(techniqueMap.get(selectedTechnique) || []).map((playbook) => (
                          <Link
                            key={playbook.id}
                            to={`/playbook/${playbook.id}`}
                            className="block rounded-lg border border-gray-800 bg-gray-950 p-3 hover:border-cyan-500/50 hover:bg-gray-800/50 transition-all group"
                          >
                            <p className="font-medium text-gray-100 group-hover:text-cyan-400 transition-colors">
                              {playbook.name}
                            </p>
                          </Link>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
