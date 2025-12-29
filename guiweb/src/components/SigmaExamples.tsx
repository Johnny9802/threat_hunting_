import { useState, useCallback, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  Library,
  Github,
  Upload,
  Search,
  FileCode,
  ArrowRightLeft,
  Copy,
  Check,
  Trash2,
  ChevronDown,
  ChevronRight,
  Loader2,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Download,
  FolderOpen,
  File,
  X,
  Plus,
  RefreshCw,
  Eye,
  Database,
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
  convertSigmaToSpl,
  listProfiles,
  type SigmaProfile,
  type MappingResult,
} from '../services/sigmaApi';

// Types for stored examples
interface SigmaExample {
  id: string;
  title: string;
  description?: string;
  sigma_yaml: string;
  spl?: string;
  mappings?: MappingResult[];
  gaps?: { field: string; impact: string; suggestions: string[] }[];
  source: 'sigmahq' | 'manual' | 'uploaded';
  source_path?: string;
  category?: string;
  level?: string;
  status?: string;
  tags?: string[];
  created_at: string;
  translated_at?: string;
  profile_id?: number;
}

// GitHub API types
interface GitHubContent {
  name: string;
  path: string;
  type: 'file' | 'dir';
  download_url: string | null;
  url: string;
}

// Popular categories for quick access
const SIGMA_CATEGORIES = [
  { name: 'All', path: '', icon: Library },
  { name: 'Windows', path: 'rules/windows', icon: FileCode },
  { name: 'Linux', path: 'rules/linux', icon: FileCode },
  { name: 'Network', path: 'rules/network', icon: FileCode },
  { name: 'Cloud', path: 'rules/cloud', icon: FileCode },
];

// Local storage key
const STORAGE_KEY = 'sigma-examples-library';

// Load examples from localStorage
const loadExamplesFromStorage = (): SigmaExample[] => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
};

// Save examples to localStorage
const saveExamplesToStorage = (examples: SigmaExample[]) => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(examples));
};

export default function SigmaExamples() {
  // State
  const [examples, setExamples] = useState<SigmaExample[]>([]);
  const [selectedExample, setSelectedExample] = useState<SigmaExample | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSource, setFilterSource] = useState<'all' | 'sigmahq' | 'manual' | 'uploaded'>('all');
  const [filterCategory] = useState('');
  const [filterTranslated, setFilterTranslated] = useState<'all' | 'yes' | 'no'>('all');
  const [activeTab, setActiveTab] = useState<'sigma' | 'spl' | 'mappings'>('sigma');
  const [copied, setCopied] = useState(false);
  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>();

  // GitHub browser state
  const [showGitHubBrowser, setShowGitHubBrowser] = useState(false);
  const [currentGitHubPath, setCurrentGitHubPath] = useState('rules/windows');
  const [gitHubContents, setGitHubContents] = useState<GitHubContent[]>([]);
  const [gitHubLoading, setGitHubLoading] = useState(false);
  const [gitHubError, setGitHubError] = useState<string | null>(null);
  const [gitHubSearchQuery, setGitHubSearchQuery] = useState('');
  const [selectedGitHubFiles, setSelectedGitHubFiles] = useState<Set<string>>(new Set());
  const [importingRules, setImportingRules] = useState(false);

  // Manual add state
  const [showAddManual, setShowAddManual] = useState(false);
  const [manualYaml, setManualYaml] = useState('');
  const [manualTitle, setManualTitle] = useState('');

  // Fetch profiles
  const { data: profiles = [] } = useQuery({
    queryKey: ['sigma-profiles'],
    queryFn: listProfiles,
  });

  // Load examples on mount
  useEffect(() => {
    const loaded = loadExamplesFromStorage();
    setExamples(loaded);
  }, []);

  // Save examples when changed
  useEffect(() => {
    if (examples.length > 0) {
      saveExamplesToStorage(examples);
    }
  }, [examples]);

  // Copy to clipboard
  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Fetch GitHub directory contents
  const fetchGitHubContents = useCallback(async (path: string) => {
    setGitHubLoading(true);
    setGitHubError(null);
    try {
      const response = await fetch(
        `https://api.github.com/repos/SigmaHQ/sigma/contents/${path}?ref=master`
      );
      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status}`);
      }
      const data: GitHubContent[] = await response.json();
      const sorted = data.sort((a, b) => {
        if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });
      setGitHubContents(sorted);
      setCurrentGitHubPath(path);
    } catch (err: any) {
      setGitHubError(err.message || 'Failed to fetch from GitHub');
    } finally {
      setGitHubLoading(false);
    }
  }, []);

  // Toggle file selection for import
  const toggleFileSelection = (path: string) => {
    const newSelection = new Set(selectedGitHubFiles);
    if (newSelection.has(path)) {
      newSelection.delete(path);
    } else {
      newSelection.add(path);
    }
    setSelectedGitHubFiles(newSelection);
  };

  // Import selected rules from GitHub
  const importSelectedRules = async () => {
    if (selectedGitHubFiles.size === 0) return;

    setImportingRules(true);
    const newExamples: SigmaExample[] = [];

    for (const path of selectedGitHubFiles) {
      try {
        // Find the item in gitHubContents
        const item = gitHubContents.find(c => c.path === path);
        if (!item?.download_url) continue;

        // Fetch the rule content
        const response = await fetch(item.download_url);
        if (!response.ok) continue;

        const yamlContent = await response.text();

        // Parse basic info from YAML
        const titleMatch = yamlContent.match(/^title:\s*(.+)$/m);
        const descMatch = yamlContent.match(/^description:\s*(.+)$/m);
        const levelMatch = yamlContent.match(/^level:\s*(.+)$/m);
        const statusMatch = yamlContent.match(/^status:\s*(.+)$/m);
        const tagsMatch = yamlContent.match(/^tags:\s*\n((?:\s+-\s*.+\n?)+)/m);

        const tags: string[] = [];
        if (tagsMatch) {
          const tagLines = tagsMatch[1].match(/-\s*(.+)/g);
          tagLines?.forEach(t => tags.push(t.replace(/^\s*-\s*/, '').trim()));
        }

        // Check if already exists
        const exists = examples.some(e => e.source_path === path);
        if (exists) continue;

        newExamples.push({
          id: crypto.randomUUID(),
          title: titleMatch?.[1] || item.name.replace('.yml', ''),
          description: descMatch?.[1],
          sigma_yaml: yamlContent,
          source: 'sigmahq',
          source_path: path,
          category: currentGitHubPath.split('/').slice(1).join('/'),
          level: levelMatch?.[1],
          status: statusMatch?.[1],
          tags,
          created_at: new Date().toISOString(),
        });
      } catch (err) {
        console.error(`Failed to import ${path}:`, err);
      }
    }

    if (newExamples.length > 0) {
      setExamples(prev => [...prev, ...newExamples]);
    }

    setSelectedGitHubFiles(new Set());
    setImportingRules(false);
    setShowGitHubBrowser(false);
  };

  // Translate a single example
  const translateExample = useMutation({
    mutationFn: async (example: SigmaExample) => {
      const result = await convertSigmaToSpl({
        sigma_yaml: example.sigma_yaml,
        profile_id: selectedProfileId,
      });
      return { example, result };
    },
    onSuccess: ({ example, result }) => {
      setExamples(prev => prev.map(e =>
        e.id === example.id
          ? {
              ...e,
              spl: result.spl,
              mappings: result.mappings,
              gaps: result.gaps,
              translated_at: new Date().toISOString(),
              profile_id: selectedProfileId,
            }
          : e
      ));
      if (selectedExample?.id === example.id) {
        setSelectedExample(prev => prev ? {
          ...prev,
          spl: result.spl,
          mappings: result.mappings,
          gaps: result.gaps,
          translated_at: new Date().toISOString(),
          profile_id: selectedProfileId,
        } : null);
      }
    },
  });

  // Translate all untranslated examples
  const translateAll = async () => {
    const untranslated = examples.filter(e => !e.spl);
    for (const example of untranslated) {
      await translateExample.mutateAsync(example);
    }
  };

  // Delete example
  const deleteExample = (id: string) => {
    setExamples(prev => prev.filter(e => e.id !== id));
    if (selectedExample?.id === id) {
      setSelectedExample(null);
    }
  };

  // Handle file upload
  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files) return;

    Array.from(files).forEach(file => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;

        const titleMatch = content.match(/^title:\s*(.+)$/m);
        const descMatch = content.match(/^description:\s*(.+)$/m);
        const levelMatch = content.match(/^level:\s*(.+)$/m);

        const newExample: SigmaExample = {
          id: crypto.randomUUID(),
          title: titleMatch?.[1] || file.name.replace('.yml', ''),
          description: descMatch?.[1],
          sigma_yaml: content,
          source: 'uploaded',
          level: levelMatch?.[1],
          created_at: new Date().toISOString(),
        };

        setExamples(prev => [...prev, newExample]);
      };
      reader.readAsText(file);
    });

    event.target.value = '';
  };

  // Add manual example
  const addManualExample = () => {
    if (!manualYaml.trim()) return;

    const titleMatch = manualYaml.match(/^title:\s*(.+)$/m);
    const descMatch = manualYaml.match(/^description:\s*(.+)$/m);
    const levelMatch = manualYaml.match(/^level:\s*(.+)$/m);

    const newExample: SigmaExample = {
      id: crypto.randomUUID(),
      title: manualTitle || titleMatch?.[1] || 'Manual Rule',
      description: descMatch?.[1],
      sigma_yaml: manualYaml,
      source: 'manual',
      level: levelMatch?.[1],
      created_at: new Date().toISOString(),
    };

    setExamples(prev => [...prev, newExample]);
    setManualYaml('');
    setManualTitle('');
    setShowAddManual(false);
  };

  // Export example
  const exportExample = (example: SigmaExample) => {
    const exportData = {
      title: example.title,
      sigma_yaml: example.sigma_yaml,
      spl: example.spl,
      mappings: example.mappings,
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${example.title.replace(/\s+/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Filtered examples
  const filteredExamples = examples.filter(e => {
    if (searchQuery && !e.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !e.description?.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    if (filterSource !== 'all' && e.source !== filterSource) return false;
    if (filterCategory && !e.category?.includes(filterCategory)) return false;
    if (filterTranslated === 'yes' && !e.spl) return false;
    if (filterTranslated === 'no' && e.spl) return false;
    return true;
  });

  // GitHub breadcrumb
  const gitHubBreadcrumbParts = currentGitHubPath.split('/').filter(Boolean);

  // Filtered GitHub contents
  const filteredGitHubContents = gitHubContents.filter(item =>
    item.name.toLowerCase().includes(gitHubSearchQuery.toLowerCase())
  );

  // Stats
  const stats = {
    total: examples.length,
    translated: examples.filter(e => e.spl).length,
    fromGitHub: examples.filter(e => e.source === 'sigmahq').length,
    manual: examples.filter(e => e.source === 'manual' || e.source === 'uploaded').length,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Library className="text-cyan-400" size={28} />
            Sigma Examples Library
          </h1>
          <p className="text-gray-400 mt-1">
            Browse, import, and translate Sigma detection rules
          </p>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4">
          <div className="text-center px-4 py-2 bg-gray-800/50 rounded-lg">
            <p className="text-2xl font-bold text-white">{stats.total}</p>
            <p className="text-xs text-gray-400">Total Rules</p>
          </div>
          <div className="text-center px-4 py-2 bg-gray-800/50 rounded-lg">
            <p className="text-2xl font-bold text-green-400">{stats.translated}</p>
            <p className="text-xs text-gray-400">Translated</p>
          </div>
        </div>
      </div>

      {/* Actions Bar */}
      <div className="flex flex-wrap items-center gap-3 p-4 bg-gray-800/30 rounded-lg border border-gray-700">
        {/* Import from GitHub */}
        <button
          onClick={() => {
            setShowGitHubBrowser(true);
            if (gitHubContents.length === 0) {
              fetchGitHubContents(currentGitHubPath);
            }
          }}
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 text-gray-200 rounded-lg hover:bg-gray-700 transition-colors"
        >
          <Github size={18} />
          Import from SigmaHQ
        </button>

        {/* Upload files */}
        <label className="flex items-center gap-2 px-4 py-2 bg-gray-800 text-gray-200 rounded-lg hover:bg-gray-700 cursor-pointer transition-colors">
          <Upload size={18} />
          Upload Files
          <input
            type="file"
            accept=".yml,.yaml"
            multiple
            onChange={handleFileUpload}
            className="hidden"
          />
        </label>

        {/* Add manual */}
        <button
          onClick={() => setShowAddManual(true)}
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 text-gray-200 rounded-lg hover:bg-gray-700 transition-colors"
        >
          <Plus size={18} />
          Add Manual
        </button>

        <div className="flex-1" />

        {/* Profile selector */}
        {profiles.length > 0 && (
          <div className="relative">
            <select
              value={selectedProfileId || ''}
              onChange={(e) => setSelectedProfileId(e.target.value ? Number(e.target.value) : undefined)}
              className="appearance-none bg-gray-800 text-gray-200 text-sm rounded-lg px-3 py-2 pr-8 border border-gray-700 focus:border-cyan-500 focus:outline-none"
            >
              <option value="">Default Profile</option>
              {profiles.map((profile: SigmaProfile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.name}
                </option>
              ))}
            </select>
            <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" size={16} />
          </div>
        )}

        {/* Translate All */}
        <button
          onClick={translateAll}
          disabled={translateExample.isPending || examples.filter(e => !e.spl).length === 0}
          className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {translateExample.isPending ? (
            <Loader2 className="animate-spin" size={18} />
          ) : (
            <RefreshCw size={18} />
          )}
          Translate All ({examples.filter(e => !e.spl).length})
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-64">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={18} />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search rules..."
            className="w-full bg-gray-800 text-gray-200 rounded-lg pl-10 pr-4 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        {/* Source filter */}
        <select
          value={filterSource}
          onChange={(e) => setFilterSource(e.target.value as any)}
          className="bg-gray-800 text-gray-200 text-sm rounded-lg px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Sources</option>
          <option value="sigmahq">SigmaHQ</option>
          <option value="manual">Manual</option>
          <option value="uploaded">Uploaded</option>
        </select>

        {/* Translated filter */}
        <select
          value={filterTranslated}
          onChange={(e) => setFilterTranslated(e.target.value as any)}
          className="bg-gray-800 text-gray-200 text-sm rounded-lg px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
        >
          <option value="all">All Status</option>
          <option value="yes">Translated</option>
          <option value="no">Not Translated</option>
        </select>
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rules List */}
        <div className="lg:col-span-1 bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
          <div className="p-3 border-b border-gray-700 bg-gray-800/50">
            <p className="text-sm text-gray-400">{filteredExamples.length} rules</p>
          </div>
          <div className="max-h-[600px] overflow-y-auto divide-y divide-gray-800">
            {filteredExamples.length === 0 ? (
              <div className="p-8 text-center text-gray-500">
                <Library size={48} className="mx-auto mb-4 opacity-50" />
                <p>No rules in library</p>
                <p className="text-sm mt-2">Import from SigmaHQ or upload files</p>
              </div>
            ) : (
              filteredExamples.map((example) => (
                <button
                  key={example.id}
                  onClick={() => setSelectedExample(example)}
                  className={cn(
                    "w-full p-3 text-left hover:bg-gray-800/50 transition-colors",
                    selectedExample?.id === example.id && "bg-cyan-500/10"
                  )}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-white truncate">{example.title}</p>
                      {example.description && (
                        <p className="text-xs text-gray-400 truncate mt-1">{example.description}</p>
                      )}
                      <div className="flex items-center gap-2 mt-2">
                        {/* Source badge */}
                        <span className={cn(
                          "px-1.5 py-0.5 rounded text-xs",
                          example.source === 'sigmahq' ? "bg-purple-500/20 text-purple-400" :
                          example.source === 'uploaded' ? "bg-blue-500/20 text-blue-400" :
                          "bg-gray-700 text-gray-400"
                        )}>
                          {example.source === 'sigmahq' ? 'SigmaHQ' : example.source}
                        </span>

                        {/* Level badge */}
                        {example.level && (
                          <span className={cn(
                            "px-1.5 py-0.5 rounded text-xs",
                            example.level === 'critical' ? "bg-red-500/20 text-red-400" :
                            example.level === 'high' ? "bg-orange-500/20 text-orange-400" :
                            example.level === 'medium' ? "bg-yellow-500/20 text-yellow-400" :
                            "bg-gray-700 text-gray-400"
                          )}>
                            {example.level}
                          </span>
                        )}

                        {/* Translated badge */}
                        {example.spl ? (
                          <CheckCircle className="text-green-400" size={14} />
                        ) : (
                          <XCircle className="text-gray-500" size={14} />
                        )}
                      </div>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Detail Panel */}
        <div className="lg:col-span-2 bg-gray-900 rounded-lg border border-gray-700 overflow-hidden">
          {selectedExample ? (
            <>
              {/* Header */}
              <div className="p-4 border-b border-gray-700 bg-gray-800/50">
                <div className="flex items-start justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-white">{selectedExample.title}</h2>
                    {selectedExample.description && (
                      <p className="text-sm text-gray-400 mt-1">{selectedExample.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-2 text-xs text-gray-500">
                      {selectedExample.category && (
                        <span className="flex items-center gap-1">
                          <FolderOpen size={12} />
                          {selectedExample.category}
                        </span>
                      )}
                      {selectedExample.translated_at && (
                        <span className="flex items-center gap-1">
                          <CheckCircle size={12} className="text-green-400" />
                          Translated
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {!selectedExample.spl && (
                      <button
                        onClick={() => translateExample.mutate(selectedExample)}
                        disabled={translateExample.isPending}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-500 text-white text-sm rounded-lg hover:bg-cyan-600 disabled:opacity-50"
                      >
                        {translateExample.isPending ? (
                          <Loader2 className="animate-spin" size={14} />
                        ) : (
                          <ArrowRightLeft size={14} />
                        )}
                        Translate
                      </button>
                    )}
                    <button
                      onClick={() => exportExample(selectedExample)}
                      className="p-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-lg"
                      title="Export"
                    >
                      <Download size={16} />
                    </button>
                    <button
                      onClick={() => deleteExample(selectedExample.id)}
                      className="p-2 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded-lg"
                      title="Delete"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex border-b border-gray-700">
                {[
                  { id: 'sigma', label: 'Sigma YAML', icon: FileCode },
                  { id: 'spl', label: 'SPL Query', icon: Database, disabled: !selectedExample.spl },
                  { id: 'mappings', label: `Mappings (${selectedExample.mappings?.length || 0})`, icon: ArrowRightLeft, disabled: !selectedExample.mappings },
                ].map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    disabled={tab.disabled}
                    className={cn(
                      "flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors",
                      activeTab === tab.id
                        ? "border-cyan-400 text-cyan-400"
                        : "border-transparent text-gray-400 hover:text-white",
                      tab.disabled && "opacity-50 cursor-not-allowed"
                    )}
                  >
                    <tab.icon size={16} />
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Tab Content */}
              <div className="p-4 max-h-[450px] overflow-auto">
                {activeTab === 'sigma' && (
                  <div className="relative">
                    <button
                      onClick={() => handleCopy(selectedExample.sigma_yaml)}
                      className="absolute top-2 right-2 p-2 text-gray-400 hover:text-white bg-gray-800 rounded"
                    >
                      {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                    </button>
                    <pre className="text-sm text-gray-300 font-mono whitespace-pre-wrap">
                      {selectedExample.sigma_yaml}
                    </pre>
                  </div>
                )}

                {activeTab === 'spl' && selectedExample.spl && (
                  <div className="space-y-4">
                    <div className="relative">
                      <button
                        onClick={() => handleCopy(selectedExample.spl!)}
                        className="absolute top-2 right-2 p-2 text-gray-400 hover:text-white bg-gray-800 rounded"
                      >
                        {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                      </button>
                      <pre className="p-4 bg-gray-800 rounded-lg text-sm text-cyan-400 font-mono whitespace-pre-wrap">
                        {selectedExample.spl}
                      </pre>
                    </div>

                    {/* Gaps */}
                    {selectedExample.gaps && selectedExample.gaps.length > 0 && (
                      <div className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                        <h4 className="font-medium text-yellow-400 flex items-center gap-2 mb-2">
                          <AlertTriangle size={16} />
                          {selectedExample.gaps.length} Gap(s) Detected
                        </h4>
                        <div className="space-y-2">
                          {selectedExample.gaps.map((gap, idx) => (
                            <div key={idx} className="text-sm">
                              <span className="text-white font-mono">{gap.field}</span>
                              <span className="text-gray-400"> - {gap.impact}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {activeTab === 'mappings' && selectedExample.mappings && (
                  <div className="space-y-2">
                    {selectedExample.mappings.map((mapping, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg"
                      >
                        <div className="flex items-center gap-3">
                          {mapping.status === 'ok' ? (
                            <CheckCircle className="text-green-400" size={16} />
                          ) : mapping.status === 'missing' ? (
                            <XCircle className="text-red-400" size={16} />
                          ) : (
                            <Info className="text-yellow-400" size={16} />
                          )}
                          <code className="text-cyan-400 text-sm">{mapping.sigma_field}</code>
                        </div>
                        <div className="flex items-center gap-2">
                          <ChevronRight className="text-gray-500" size={16} />
                          <code className={cn(
                            "text-sm",
                            mapping.target_field ? "text-green-400" : "text-red-400"
                          )}>
                            {mapping.target_field || 'UNMAPPED'}
                          </code>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-gray-500 p-12">
              <Eye size={48} className="mb-4 opacity-50" />
              <p>Select a rule to view details</p>
              <p className="text-sm mt-2">Choose from the list or import new rules</p>
            </div>
          )}
        </div>
      </div>

      {/* GitHub Browser Modal */}
      {showGitHubBrowser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-950/80 backdrop-blur-sm">
          <div className="bg-gray-900 rounded-xl border border-gray-700 w-full max-w-4xl max-h-[80vh] flex flex-col shadow-2xl">
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <Github className="text-cyan-400" size={24} />
                <div>
                  <h2 className="text-lg font-semibold text-white">Import from SigmaHQ</h2>
                  <p className="text-sm text-gray-400">Select rules to add to your library</p>
                </div>
              </div>
              <button
                onClick={() => {
                  setShowGitHubBrowser(false);
                  setSelectedGitHubFiles(new Set());
                }}
                className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg"
              >
                <X size={20} />
              </button>
            </div>

            {/* Category tabs */}
            <div className="flex items-center gap-2 p-3 border-b border-gray-800 overflow-x-auto">
              {SIGMA_CATEGORIES.slice(1).map((cat) => (
                <button
                  key={cat.path}
                  onClick={() => fetchGitHubContents(cat.path)}
                  className={cn(
                    "px-3 py-1.5 rounded-lg text-sm font-medium whitespace-nowrap transition-colors",
                    currentGitHubPath.startsWith(cat.path)
                      ? "bg-cyan-500/20 text-cyan-400"
                      : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
                  )}
                >
                  {cat.name}
                </button>
              ))}
            </div>

            {/* Breadcrumb & Search */}
            <div className="flex items-center justify-between p-3 border-b border-gray-800">
              <div className="flex items-center gap-1 text-sm">
                {gitHubBreadcrumbParts.map((part, idx) => (
                  <div key={idx} className="flex items-center gap-1">
                    {idx > 0 && <ChevronRight className="text-gray-600" size={14} />}
                    <button
                      onClick={() => fetchGitHubContents(gitHubBreadcrumbParts.slice(0, idx + 1).join('/'))}
                      className={cn(
                        idx === gitHubBreadcrumbParts.length - 1
                          ? "text-white font-medium"
                          : "text-cyan-400 hover:underline"
                      )}
                    >
                      {part}
                    </button>
                  </div>
                ))}
              </div>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
                <input
                  type="text"
                  value={gitHubSearchQuery}
                  onChange={(e) => setGitHubSearchQuery(e.target.value)}
                  placeholder="Filter..."
                  className="w-48 bg-gray-800 text-gray-200 text-sm rounded-lg pl-9 pr-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* File List */}
            <div className="flex-1 overflow-y-auto">
              {gitHubLoading ? (
                <div className="flex items-center justify-center p-12">
                  <Loader2 className="animate-spin text-cyan-400" size={32} />
                </div>
              ) : gitHubError ? (
                <div className="p-4">
                  <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400">
                    {gitHubError}
                  </div>
                </div>
              ) : (
                <div className="divide-y divide-gray-800">
                  {currentGitHubPath !== 'rules' && (
                    <button
                      onClick={() => {
                        const parts = currentGitHubPath.split('/');
                        parts.pop();
                        fetchGitHubContents(parts.join('/'));
                      }}
                      className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-800/50"
                    >
                      <FolderOpen className="text-yellow-400" size={18} />
                      <span className="text-gray-300">..</span>
                    </button>
                  )}
                  {filteredGitHubContents.map((item) => {
                    const isYml = item.name.endsWith('.yml');
                    const isSelected = selectedGitHubFiles.has(item.path);
                    const alreadyImported = examples.some(e => e.source_path === item.path);

                    return (
                      <button
                        key={item.path}
                        onClick={() => {
                          if (item.type === 'dir') {
                            fetchGitHubContents(item.path);
                          } else if (isYml && !alreadyImported) {
                            toggleFileSelection(item.path);
                          }
                        }}
                        disabled={alreadyImported}
                        className={cn(
                          "w-full flex items-center gap-3 px-4 py-3 text-left transition-colors",
                          isSelected && "bg-cyan-500/10",
                          alreadyImported ? "opacity-50 cursor-not-allowed" : "hover:bg-gray-800/50"
                        )}
                      >
                        {item.type === 'dir' ? (
                          <FolderOpen className="text-yellow-400" size={18} />
                        ) : isYml ? (
                          <div className={cn(
                            "w-5 h-5 rounded border flex items-center justify-center",
                            isSelected ? "bg-cyan-500 border-cyan-500" : "border-gray-600"
                          )}>
                            {isSelected && <Check size={14} className="text-white" />}
                          </div>
                        ) : (
                          <File className="text-gray-500" size={18} />
                        )}
                        <span className={cn(
                          "flex-1 truncate",
                          item.type === 'dir' ? "text-gray-200" :
                          isYml ? "text-gray-300" : "text-gray-500"
                        )}>
                          {item.name}
                        </span>
                        {alreadyImported && (
                          <span className="text-xs text-gray-500">Already imported</span>
                        )}
                        {item.type === 'dir' && (
                          <ChevronRight className="text-gray-600" size={16} />
                        )}
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-gray-700 flex items-center justify-between">
              <p className="text-sm text-gray-400">
                {selectedGitHubFiles.size} file(s) selected
              </p>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setShowGitHubBrowser(false);
                    setSelectedGitHubFiles(new Set());
                  }}
                  className="px-4 py-2 text-gray-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  onClick={importSelectedRules}
                  disabled={selectedGitHubFiles.size === 0 || importingRules}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {importingRules ? (
                    <Loader2 className="animate-spin" size={18} />
                  ) : (
                    <Download size={18} />
                  )}
                  Import Selected
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add Manual Modal */}
      {showAddManual && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-950/80 backdrop-blur-sm">
          <div className="bg-gray-900 rounded-xl border border-gray-700 w-full max-w-2xl shadow-2xl">
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <h2 className="text-lg font-semibold text-white">Add Manual Rule</h2>
              <button
                onClick={() => setShowAddManual(false)}
                className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg"
              >
                <X size={20} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Title (optional - will be extracted from YAML)
                </label>
                <input
                  type="text"
                  value={manualTitle}
                  onChange={(e) => setManualTitle(e.target.value)}
                  placeholder="Rule title"
                  className="w-full bg-gray-800 text-gray-200 rounded-lg px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-1">
                  Sigma YAML
                </label>
                <textarea
                  value={manualYaml}
                  onChange={(e) => setManualYaml(e.target.value)}
                  placeholder="Paste your Sigma rule YAML here..."
                  className="w-full h-64 bg-gray-800 text-gray-200 font-mono text-sm rounded-lg px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none resize-none"
                />
              </div>
            </div>
            <div className="p-4 border-t border-gray-700 flex justify-end gap-2">
              <button
                onClick={() => setShowAddManual(false)}
                className="px-4 py-2 text-gray-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={addManualExample}
                disabled={!manualYaml.trim()}
                className="px-4 py-2 bg-cyan-500 text-white rounded-lg hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Add Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
