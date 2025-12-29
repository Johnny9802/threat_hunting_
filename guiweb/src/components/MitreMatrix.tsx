import { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Loader2,
  AlertCircle,
  FileCode,
  Target,
  Info,
} from 'lucide-react';
import { usePlaybooks } from '../hooks/usePlaybooks';

// MITRE ATT&CK Enterprise Tactics (in order)
const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance', short: 'Recon' },
  { id: 'TA0042', name: 'Resource Development', short: 'Resource Dev' },
  { id: 'TA0001', name: 'Initial Access', short: 'Initial Access' },
  { id: 'TA0002', name: 'Execution', short: 'Execution' },
  { id: 'TA0003', name: 'Persistence', short: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation', short: 'Priv Esc' },
  { id: 'TA0005', name: 'Defense Evasion', short: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access', short: 'Cred Access' },
  { id: 'TA0007', name: 'Discovery', short: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement', short: 'Lateral Move' },
  { id: 'TA0009', name: 'Collection', short: 'Collection' },
  { id: 'TA0011', name: 'Command and Control', short: 'C2' },
  { id: 'TA0010', name: 'Exfiltration', short: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact', short: 'Impact' },
];

export default function MitreMatrix() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);
  const [expandedTechnique, setExpandedTechnique] = useState<string | null>(null);

  const { data: playbooks, isLoading, isError, error } = usePlaybooks();

  // Build technique-to-playbooks mapping
  const techniqueMap = useMemo(() => {
    if (!playbooks) return new Map();

    const map = new Map<string, typeof playbooks>();

    playbooks.forEach((playbook) => {
      if (playbook.mitre?.technique) {
        const techniqueId = playbook.mitre.technique;
        if (!map.has(techniqueId)) {
          map.set(techniqueId, []);
        }
        map.get(techniqueId)!.push(playbook);
      }
    });

    return map;
  }, [playbooks]);

  // Build tactic-to-techniques mapping
  const tacticTechniqueMap = useMemo(() => {
    if (!playbooks) return new Map();

    const map = new Map<string, Set<string>>();

    playbooks.forEach((playbook) => {
      const tactic = playbook.mitre?.tactic || playbook.tactic;
      const technique = playbook.mitre?.technique;

      if (tactic && technique) {
        if (!map.has(tactic)) {
          map.set(tactic, new Set());
        }
        map.get(tactic)!.add(technique);
      }
    });

    return map;
  }, [playbooks]);

  // Filter techniques based on search
  const filteredTechniques = useMemo(() => {
    if (!searchQuery) return Array.from(techniqueMap.keys());

    const query = searchQuery.toLowerCase();
    return Array.from(techniqueMap.keys()).filter((techniqueId) => {
      const playbooksForTechnique = techniqueMap.get(techniqueId) || [];
      return (
        techniqueId.toLowerCase().includes(query) ||
        playbooksForTechnique.some(
          (pb: { name: string; description: string }) =>
            pb.name.toLowerCase().includes(query) ||
            pb.description.toLowerCase().includes(query)
        )
      );
    });
  }, [techniqueMap, searchQuery]);

  // Get coverage stats
  const coverageStats = useMemo(() => {
    const totalTechniques = techniqueMap.size;
    const totalPlaybooks = playbooks?.length || 0;

    const tacticCoverage = MITRE_TACTICS.map((tactic) => ({
      ...tactic,
      techniques: tacticTechniqueMap.get(tactic.name)?.size || 0,
    }));

    return {
      totalTechniques,
      totalPlaybooks,
      tacticCoverage,
    };
  }, [techniqueMap, playbooks, tacticTechniqueMap]);

  const handleTacticClick = (tacticName: string) => {
    setSelectedTactic(selectedTactic === tacticName ? null : tacticName);
  };

  const handleTechniqueClick = (techniqueId: string) => {
    setExpandedTechnique(expandedTechnique === techniqueId ? null : techniqueId);
  };

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
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-100">MITRE ATT&CK Matrix</h1>
          <p className="text-gray-400 mt-1">Enterprise tactics and techniques coverage</p>
        </div>
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 rounded-lg bg-gray-800 px-4 py-2 text-sm font-medium text-gray-300 hover:bg-gray-700 transition-colors"
        >
          <ExternalLink size={16} />
          MITRE ATT&CK Website
        </a>
      </div>

      {/* Coverage Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/10 p-3">
              <Target className="h-6 w-6 text-cyan-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100">{coverageStats.totalTechniques}</p>
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
              <p className="text-2xl font-bold text-gray-100">{coverageStats.totalPlaybooks}</p>
              <p className="text-sm text-gray-400">Total Playbooks</p>
            </div>
          </div>
        </div>
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-green-500/10 p-3">
              <FileCode className="h-6 w-6 text-green-500" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-100">
                {Math.round((coverageStats.totalTechniques / 193) * 100)}%
              </p>
              <p className="text-sm text-gray-400">ATT&CK Coverage</p>
            </div>
          </div>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
        <input
          type="text"
          placeholder="Search techniques or playbooks..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full rounded-lg border border-gray-800 bg-gray-900 pl-10 pr-4 py-3 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
        />
      </div>

      {/* Info Banner */}
      <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-4">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-blue-300">
              This matrix shows all MITRE ATT&CK techniques covered by your playbooks. Click on a
              tactic to view techniques, and click on a technique to see associated playbooks.
            </p>
          </div>
        </div>
      </div>

      {/* Tactics Matrix */}
      <div className="space-y-2">
        {MITRE_TACTICS.map((tactic) => {
          const techniquesForTactic = tacticTechniqueMap.get(tactic.name);
          const techniqueCount = techniquesForTactic?.size || 0;
          const isExpanded = selectedTactic === tactic.name;

          return (
            <div key={tactic.id} className="rounded-lg border border-gray-800 bg-gray-900">
              {/* Tactic Header */}
              <button
                onClick={() => handleTacticClick(tactic.name)}
                className="flex w-full items-center justify-between px-6 py-4 text-left hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center gap-4">
                  {isExpanded ? (
                    <ChevronDown className="h-5 w-5 text-gray-400" />
                  ) : (
                    <ChevronRight className="h-5 w-5 text-gray-400" />
                  )}
                  <Shield className="h-5 w-5 text-cyan-500" />
                  <div>
                    <h3 className="font-semibold text-gray-100">{tactic.name}</h3>
                    <p className="text-sm text-gray-500">{tactic.id}</p>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="rounded-full bg-cyan-500/10 px-3 py-1 text-sm font-semibold text-cyan-400">
                    {techniqueCount} technique{techniqueCount !== 1 ? 's' : ''}
                  </span>
                </div>
              </button>

              {/* Techniques List */}
              {isExpanded && techniquesForTactic && (
                <div className="border-t border-gray-800 bg-gray-950/50">
                  {(Array.from(techniquesForTactic) as string[])
                    .filter((techniqueId) => filteredTechniques.includes(techniqueId))
                    .map((techniqueId) => {
                      const playbooksForTechnique = techniqueMap.get(techniqueId) || [];
                      const isExpanded = expandedTechnique === techniqueId;

                      return (
                        <div key={techniqueId} className="border-b border-gray-800 last:border-b-0">
                          {/* Technique */}
                          <button
                            onClick={() => handleTechniqueClick(techniqueId)}
                            className="flex w-full items-center justify-between px-6 py-3 text-left hover:bg-gray-800/50 transition-colors"
                          >
                            <div className="flex items-center gap-3">
                              {isExpanded ? (
                                <ChevronDown className="h-4 w-4 text-gray-500" />
                              ) : (
                                <ChevronRight className="h-4 w-4 text-gray-500" />
                              )}
                              <Target className="h-4 w-4 text-gray-500" />
                              <code className="rounded bg-gray-800 px-2 py-1 text-sm text-cyan-400">
                                {techniqueId}
                              </code>
                            </div>
                            <span className="rounded-full bg-gray-800 px-2.5 py-0.5 text-xs font-semibold text-gray-400">
                              {playbooksForTechnique.length} playbook
                              {playbooksForTechnique.length !== 1 ? 's' : ''}
                            </span>
                          </button>

                          {/* Playbooks */}
                          {isExpanded && (
                            <div className="bg-gray-900/50 px-6 py-2 space-y-2">
                              {playbooksForTechnique.map((playbook: { id: string; name: string; description: string }) => (
                                <Link
                                  key={playbook.id}
                                  to={`/playbook/${playbook.id}`}
                                  className="block rounded-lg border border-gray-800 bg-gray-950 p-3 hover:border-cyan-500/50 hover:bg-gray-800/50 transition-all group"
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
                      );
                    })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
