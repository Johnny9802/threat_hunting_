import { useState, useCallback } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  ArrowRightLeft,
  FileCode,
  Sparkles,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Loader2,
  Upload,
  Github,
  FolderOpen,
  File,
  Search,
  X,
  ExternalLink,
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
  convertSigmaToSpl,
  convertSplToSigma,
  generateFromDescription,
  listProfiles,
  getSigmaLLMStatus,
  type ConversionResponse,
  type SigmaProfile,
} from '../services/sigmaApi';

type ConversionMode = 'sigma-to-spl' | 'spl-to-sigma' | 'describe';

// SigmaHQ GitHub API types
interface GitHubContent {
  name: string;
  path: string;
  type: 'file' | 'dir';
  download_url: string | null;
  url: string;
}

interface SigmaCategory {
  name: string;
  path: string;
  description: string;
}

// Popular Sigma rule categories
const SIGMA_CATEGORIES: SigmaCategory[] = [
  { name: 'Windows', path: 'rules/windows', description: 'Windows-specific detection rules' },
  { name: 'Linux', path: 'rules/linux', description: 'Linux-specific detection rules' },
  { name: 'macOS', path: 'rules/macos', description: 'macOS-specific detection rules' },
  { name: 'Network', path: 'rules/network', description: 'Network traffic detection rules' },
  { name: 'Cloud', path: 'rules/cloud', description: 'Cloud platform detection rules' },
  { name: 'Web', path: 'rules/web', description: 'Web application detection rules' },
];

export default function SigmaConverter() {
  const [mode, setMode] = useState<ConversionMode>('sigma-to-spl');
  const [input, setInput] = useState('');
  const [result, setResult] = useState<ConversionResponse | null>(null);
  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>();
  const [activeTab, setActiveTab] = useState<'output' | 'prerequisites' | 'mappings' | 'gaps' | 'health'>('output');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // GitHub browser state
  const [showBrowser, setShowBrowser] = useState(false);
  const [currentPath, setCurrentPath] = useState('rules/windows');
  const [browserContents, setBrowserContents] = useState<GitHubContent[]>([]);
  const [browserLoading, setBrowserLoading] = useState(false);
  const [browserError, setBrowserError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [rulePreview, setRulePreview] = useState<string | null>(null);
  const [loadingRule, setLoadingRule] = useState(false);

  // Fetch profiles
  const { data: profiles = [] } = useQuery({
    queryKey: ['sigma-profiles'],
    queryFn: listProfiles,
  });

  // Fetch LLM status
  const { data: llmStatus } = useQuery({
    queryKey: ['sigma-llm-status'],
    queryFn: getSigmaLLMStatus,
  });

  // Conversion mutation
  const conversionMutation = useMutation({
    mutationFn: async () => {
      setError(null);
      if (mode === 'sigma-to-spl') {
        return convertSigmaToSpl({
          sigma_yaml: input,
          profile_id: selectedProfileId,
        });
      } else if (mode === 'spl-to-sigma') {
        return convertSplToSigma({
          spl_query: input,
          title: 'Converted Rule',
        });
      } else {
        return generateFromDescription({
          description: input,
          level: 'medium',
          include_false_positives: true,
          include_attack_techniques: true,
        });
      }
    },
    onSuccess: (data) => {
      setResult(data);
      setActiveTab('output');
    },
    onError: (err: any) => {
      setError(err.response?.data?.detail || err.message || 'Conversion failed');
    },
  });

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Fetch GitHub directory contents
  const fetchGitHubContents = useCallback(async (path: string) => {
    setBrowserLoading(true);
    setBrowserError(null);
    try {
      const response = await fetch(
        `https://api.github.com/repos/SigmaHQ/sigma/contents/${path}?ref=master`
      );
      if (!response.ok) {
        throw new Error(`GitHub API error: ${response.status}`);
      }
      const data: GitHubContent[] = await response.json();
      // Sort: directories first, then files
      const sorted = data.sort((a, b) => {
        if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
        return a.name.localeCompare(b.name);
      });
      setBrowserContents(sorted);
      setCurrentPath(path);
    } catch (err: any) {
      setBrowserError(err.message || 'Failed to fetch from GitHub');
    } finally {
      setBrowserLoading(false);
    }
  }, []);

  // Fetch a specific Sigma rule from GitHub
  const fetchSigmaRule = useCallback(async (downloadUrl: string, name: string) => {
    setLoadingRule(true);
    setSelectedRule(name);
    try {
      const response = await fetch(downloadUrl);
      if (!response.ok) {
        throw new Error(`Failed to fetch rule: ${response.status}`);
      }
      const content = await response.text();
      setRulePreview(content);
    } catch (err: any) {
      setBrowserError(err.message || 'Failed to fetch rule');
      setRulePreview(null);
    } finally {
      setLoadingRule(false);
    }
  }, []);

  // Load rule into input
  const loadRuleToInput = useCallback(() => {
    if (rulePreview) {
      setInput(rulePreview);
      setMode('sigma-to-spl');
      setShowBrowser(false);
      setRulePreview(null);
      setSelectedRule(null);
    }
  }, [rulePreview]);

  // Handle file upload
  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setInput(content);
      setMode('sigma-to-spl');
    };
    reader.onerror = () => {
      setError('Failed to read file');
    };
    reader.readAsText(file);
    event.target.value = ''; // Reset input
  }, []);

  // Open browser and fetch initial contents
  const openBrowser = useCallback(() => {
    setShowBrowser(true);
    if (browserContents.length === 0) {
      fetchGitHubContents(currentPath);
    }
  }, [browserContents.length, currentPath, fetchGitHubContents]);

  // Navigate to parent directory
  const navigateUp = useCallback(() => {
    const parts = currentPath.split('/');
    if (parts.length > 1) {
      parts.pop();
      fetchGitHubContents(parts.join('/'));
    }
  }, [currentPath, fetchGitHubContents]);

  // Filter contents based on search
  const filteredContents = browserContents.filter(item =>
    item.name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Get breadcrumb parts
  const breadcrumbParts = currentPath.split('/').filter(Boolean);

  const getOutputText = () => {
    if (!result) return '';
    if (mode === 'sigma-to-spl') return result.spl;
    return result.sigma_yaml || '';
  };

  const placeholderText = {
    'sigma-to-spl': `title: Mimikatz Detection
status: stable
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains:
      - 'sekurlsa::logonpasswords'
      - 'lsadump::sam'
  condition: selection
level: critical`,
    'spl-to-sigma': `index=windows sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| where match(CommandLine, "(?i).*sekurlsa.*") OR match(CommandLine, "(?i).*lsadump.*")
| stats count by User, Image, CommandLine`,
    'describe': `Detect when mimikatz is used to dump credentials from LSASS memory.
The attacker might use commands like sekurlsa::logonpasswords or lsadump::sam
to extract passwords and hashes from the system.`,
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Sigma Translator</h1>
          <p className="text-gray-400 mt-1">Convert between Sigma rules and Splunk SPL queries</p>
        </div>
        {llmStatus && (
          <div className={cn(
            "flex items-center gap-2 px-3 py-1.5 rounded-full text-sm",
            llmStatus.available
              ? "bg-green-500/10 text-green-400"
              : "bg-gray-700/50 text-gray-400"
          )}>
            <Sparkles size={14} />
            <span>AI: {llmStatus.available ? llmStatus.provider : 'Offline'}</span>
          </div>
        )}
      </div>

      {/* Mode Selector */}
      <div className="flex gap-2 p-1 bg-gray-800/50 rounded-lg w-fit">
        <button
          onClick={() => { setMode('sigma-to-spl'); setResult(null); setError(null); }}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
            mode === 'sigma-to-spl'
              ? "bg-cyan-500/20 text-cyan-400"
              : "text-gray-400 hover:text-gray-200"
          )}
        >
          <FileCode size={16} />
          Sigma → SPL
        </button>
        <button
          onClick={() => { setMode('spl-to-sigma'); setResult(null); setError(null); }}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
            mode === 'spl-to-sigma'
              ? "bg-cyan-500/20 text-cyan-400"
              : "text-gray-400 hover:text-gray-200"
          )}
        >
          <ArrowRightLeft size={16} />
          SPL → Sigma
        </button>
        <button
          onClick={() => { setMode('describe'); setResult(null); setError(null); }}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
            mode === 'describe'
              ? "bg-cyan-500/20 text-cyan-400"
              : "text-gray-400 hover:text-gray-200"
          )}
          disabled={!llmStatus?.available}
          title={!llmStatus?.available ? "Requires AI to be configured" : ""}
        >
          <Sparkles size={16} />
          Describe → Rule
        </button>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Panel */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">
              {mode === 'sigma-to-spl' ? 'Sigma YAML' : mode === 'spl-to-sigma' ? 'Splunk SPL' : 'Description'}
            </h2>
            <div className="flex items-center gap-2">
              {mode === 'sigma-to-spl' && (
                <>
                  {/* Upload file button */}
                  <label className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 hover:text-white cursor-pointer transition-colors bg-gray-800 rounded-lg hover:bg-gray-700">
                    <Upload size={14} />
                    Upload
                    <input
                      type="file"
                      accept=".yml,.yaml"
                      onChange={handleFileUpload}
                      className="hidden"
                    />
                  </label>
                  {/* Browse SigmaHQ button */}
                  <button
                    onClick={openBrowser}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 hover:text-white transition-colors bg-gray-800 rounded-lg hover:bg-gray-700"
                  >
                    <Github size={14} />
                    Browse SigmaHQ
                  </button>
                </>
              )}
              {mode === 'sigma-to-spl' && profiles.length > 0 && (
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
            </div>
          </div>

          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={placeholderText[mode]}
            className="w-full h-80 bg-gray-900 text-gray-100 font-mono text-sm rounded-lg border border-gray-700 p-4 focus:border-cyan-500 focus:outline-none resize-none"
          />

          <button
            onClick={() => conversionMutation.mutate()}
            disabled={!input.trim() || conversionMutation.isPending}
            className={cn(
              "w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-medium transition-colors",
              conversionMutation.isPending
                ? "bg-gray-700 text-gray-400 cursor-not-allowed"
                : "bg-cyan-500 text-white hover:bg-cyan-600"
            )}
          >
            {conversionMutation.isPending ? (
              <>
                <Loader2 className="animate-spin" size={18} />
                Converting...
              </>
            ) : (
              <>
                <ArrowRightLeft size={18} />
                Convert
              </>
            )}
          </button>

          {error && (
            <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
              <XCircle className="text-red-400 flex-shrink-0 mt-0.5" size={18} />
              <p className="text-red-400 text-sm">{error}</p>
            </div>
          )}
        </div>

        {/* Output Panel */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">
              {mode === 'sigma-to-spl' ? 'Splunk SPL' : 'Sigma YAML'}
            </h2>
            {result && (
              <button
                onClick={() => handleCopy(getOutputText())}
                className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 hover:text-white transition-colors"
              >
                {copied ? <Check size={14} className="text-green-400" /> : <Copy size={14} />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            )}
          </div>

          {/* Output Tabs */}
          {result && (
            <div className="flex gap-1 p-1 bg-gray-800/50 rounded-lg overflow-x-auto">
              {['output', 'prerequisites', 'mappings', 'gaps', 'health'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab as typeof activeTab)}
                  className={cn(
                    "px-3 py-1.5 rounded text-sm font-medium whitespace-nowrap transition-colors",
                    activeTab === tab
                      ? "bg-gray-700 text-white"
                      : "text-gray-400 hover:text-gray-200"
                  )}
                >
                  {tab === 'output' ? (mode === 'sigma-to-spl' ? 'SPL' : 'Sigma') :
                   tab === 'prerequisites' ? 'Prerequisites' :
                   tab === 'mappings' ? `Mappings (${result.mappings.length})` :
                   tab === 'gaps' ? `Gaps (${result.gaps.length})` :
                   `Health (${result.health_checks.length})`}
                </button>
              ))}
            </div>
          )}

          {/* Tab Content */}
          <div className="bg-gray-900 rounded-lg border border-gray-700 h-80 overflow-auto">
            {!result ? (
              <div className="h-full flex items-center justify-center text-gray-500">
                <p>Conversion output will appear here</p>
              </div>
            ) : activeTab === 'output' ? (
              <pre className="p-4 text-sm text-gray-100 font-mono whitespace-pre-wrap">
                {getOutputText()}
              </pre>
            ) : activeTab === 'prerequisites' ? (
              <div className="p-4 space-y-4">
                {result.prerequisites.required_logs?.map((log, idx) => (
                  <div key={idx} className="p-3 bg-gray-800/50 rounded-lg">
                    <h4 className="font-medium text-white">{log.name}</h4>
                    <p className="text-sm text-gray-400 mt-1">{log.description}</p>
                    {log.windows_channel && (
                      <p className="text-xs text-gray-500 mt-2">Channel: {log.windows_channel}</p>
                    )}
                    {log.setup_instructions.length > 0 && (
                      <div className="mt-2">
                        <p className="text-xs font-medium text-gray-400">Setup:</p>
                        <ul className="text-xs text-gray-500 list-disc list-inside mt-1">
                          {log.setup_instructions.map((step, i) => (
                            <li key={i}>{step}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
                {result.prerequisites.event_ids?.length > 0 && (
                  <div className="p-3 bg-gray-800/50 rounded-lg">
                    <h4 className="font-medium text-white">Event IDs</h4>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {result.prerequisites.event_ids.map((evt, idx) => (
                        <span key={idx} className="px-2 py-1 bg-gray-700 rounded text-xs text-gray-300">
                          {evt.id}: {evt.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : activeTab === 'mappings' ? (
              <div className="p-4">
                <div className="space-y-2">
                  {result.mappings.map((mapping, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 bg-gray-800/50 rounded">
                      <div className="flex items-center gap-2">
                        {mapping.status === 'ok' ? (
                          <CheckCircle className="text-green-400" size={16} />
                        ) : mapping.status === 'missing' ? (
                          <XCircle className="text-red-400" size={16} />
                        ) : (
                          <Info className="text-yellow-400" size={16} />
                        )}
                        <span className="text-gray-300 font-mono text-sm">{mapping.sigma_field}</span>
                      </div>
                      <span className="text-gray-400 font-mono text-sm">
                        → {mapping.target_field || 'UNMAPPED'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : activeTab === 'gaps' ? (
              <div className="p-4 space-y-3">
                {result.gaps.length === 0 ? (
                  <p className="text-green-400 flex items-center gap-2">
                    <CheckCircle size={16} />
                    No gaps detected - all fields are mapped!
                  </p>
                ) : (
                  result.gaps.map((gap, idx) => (
                    <div key={idx} className="p-3 bg-yellow-500/10 border border-yellow-500/20 rounded-lg">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="text-yellow-400 flex-shrink-0 mt-0.5" size={16} />
                        <div>
                          <p className="font-medium text-yellow-400">{gap.field}</p>
                          <p className="text-sm text-gray-400 mt-1">{gap.impact}</p>
                          {gap.suggestions.length > 0 && (
                            <ul className="text-sm text-gray-500 list-disc list-inside mt-2">
                              {gap.suggestions.map((s, i) => (
                                <li key={i}>{s}</li>
                              ))}
                            </ul>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            ) : (
              <div className="p-4 space-y-3">
                {result.health_checks.map((check, idx) => (
                  <div key={idx} className="p-3 bg-gray-800/50 rounded-lg">
                    <h4 className="font-medium text-white flex items-center gap-2">
                      <Info className="text-cyan-400" size={16} />
                      {check.name}
                    </h4>
                    <p className="text-sm text-gray-400 mt-1">{check.description}</p>
                    <div className="mt-2 p-2 bg-gray-900 rounded">
                      <code className="text-xs text-cyan-400 font-mono">{check.query}</code>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Correlation Notes */}
          {result?.correlation_notes && (
            <div className="p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
              <div className="flex items-start gap-2">
                <Info className="text-blue-400 flex-shrink-0 mt-0.5" size={16} />
                <div>
                  <p className="font-medium text-blue-400">Notes</p>
                  <pre className="text-sm text-gray-300 mt-1 whitespace-pre-wrap">{result.correlation_notes}</pre>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* SigmaHQ Browser Modal */}
      {showBrowser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-gray-950/80 backdrop-blur-sm">
          <div className="bg-gray-900 rounded-xl border border-gray-700 w-full max-w-5xl max-h-[85vh] flex flex-col shadow-2xl">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <Github className="text-cyan-400" size={24} />
                <div>
                  <h2 className="text-lg font-semibold text-white">SigmaHQ Rules Browser</h2>
                  <p className="text-sm text-gray-400">Browse and select Sigma detection rules from the official repository</p>
                </div>
              </div>
              <button
                onClick={() => {
                  setShowBrowser(false);
                  setRulePreview(null);
                  setSelectedRule(null);
                }}
                className="p-2 text-gray-400 hover:text-white hover:bg-gray-800 rounded-lg transition-colors"
              >
                <X size={20} />
              </button>
            </div>

            {/* Category Quick Links */}
            <div className="flex items-center gap-2 p-3 border-b border-gray-800 overflow-x-auto">
              {SIGMA_CATEGORIES.map((cat) => (
                <button
                  key={cat.path}
                  onClick={() => fetchGitHubContents(cat.path)}
                  className={cn(
                    "px-3 py-1.5 rounded-lg text-sm font-medium whitespace-nowrap transition-colors",
                    currentPath.startsWith(cat.path)
                      ? "bg-cyan-500/20 text-cyan-400"
                      : "bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700"
                  )}
                >
                  {cat.name}
                </button>
              ))}
              <a
                href="https://github.com/SigmaHQ/sigma/tree/master/rules"
                target="_blank"
                rel="noopener noreferrer"
                className="px-3 py-1.5 rounded-lg text-sm font-medium text-gray-400 hover:text-white flex items-center gap-1"
              >
                <ExternalLink size={14} />
                View on GitHub
              </a>
            </div>

            {/* Breadcrumb & Search */}
            <div className="flex items-center justify-between p-3 border-b border-gray-800">
              {/* Breadcrumb */}
              <div className="flex items-center gap-1 text-sm overflow-x-auto">
                <button
                  onClick={() => fetchGitHubContents('rules')}
                  className="text-cyan-400 hover:underline"
                >
                  rules
                </button>
                {breadcrumbParts.slice(1).map((part, idx) => (
                  <div key={idx} className="flex items-center gap-1">
                    <ChevronRight className="text-gray-600" size={14} />
                    <button
                      onClick={() => fetchGitHubContents(breadcrumbParts.slice(0, idx + 2).join('/'))}
                      className={cn(
                        idx === breadcrumbParts.length - 2
                          ? "text-white font-medium"
                          : "text-cyan-400 hover:underline"
                      )}
                    >
                      {part}
                    </button>
                  </div>
                ))}
              </div>

              {/* Search */}
              <div className="relative ml-4 flex-shrink-0">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" size={16} />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter..."
                  className="w-48 bg-gray-800 text-gray-200 text-sm rounded-lg pl-9 pr-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-hidden flex">
              {/* File List */}
              <div className="w-1/2 overflow-y-auto border-r border-gray-800">
                {browserLoading ? (
                  <div className="flex items-center justify-center p-12">
                    <Loader2 className="animate-spin text-cyan-400" size={32} />
                  </div>
                ) : browserError ? (
                  <div className="p-4">
                    <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                      <XCircle className="text-red-400 flex-shrink-0 mt-0.5" size={18} />
                      <div>
                        <p className="text-red-400 font-medium">Error loading contents</p>
                        <p className="text-sm text-gray-400 mt-1">{browserError}</p>
                        <button
                          onClick={() => fetchGitHubContents(currentPath)}
                          className="mt-2 text-sm text-cyan-400 hover:underline"
                        >
                          Try again
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="divide-y divide-gray-800">
                    {/* Back button */}
                    {currentPath !== 'rules' && (
                      <button
                        onClick={navigateUp}
                        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-800/50 transition-colors"
                      >
                        <FolderOpen className="text-yellow-400" size={18} />
                        <span className="text-gray-300">..</span>
                      </button>
                    )}

                    {/* Directory/File items */}
                    {filteredContents.map((item) => (
                      <button
                        key={item.path}
                        onClick={() => {
                          if (item.type === 'dir') {
                            fetchGitHubContents(item.path);
                            setRulePreview(null);
                            setSelectedRule(null);
                          } else if (item.download_url && item.name.endsWith('.yml')) {
                            fetchSigmaRule(item.download_url, item.name);
                          }
                        }}
                        className={cn(
                          "w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-gray-800/50 transition-colors",
                          selectedRule === item.name && "bg-cyan-500/10"
                        )}
                      >
                        {item.type === 'dir' ? (
                          <FolderOpen className="text-yellow-400 flex-shrink-0" size={18} />
                        ) : (
                          <File className={cn(
                            "flex-shrink-0",
                            item.name.endsWith('.yml') ? "text-cyan-400" : "text-gray-500"
                          )} size={18} />
                        )}
                        <span className={cn(
                          "truncate",
                          item.type === 'dir' ? "text-gray-200" :
                          item.name.endsWith('.yml') ? "text-gray-300" : "text-gray-500"
                        )}>
                          {item.name}
                        </span>
                        {item.type === 'dir' && (
                          <ChevronRight className="ml-auto text-gray-600" size={16} />
                        )}
                      </button>
                    ))}

                    {filteredContents.length === 0 && !browserLoading && (
                      <div className="p-8 text-center text-gray-500">
                        No matching files found
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Preview Panel */}
              <div className="w-1/2 overflow-y-auto flex flex-col">
                {loadingRule ? (
                  <div className="flex-1 flex items-center justify-center">
                    <Loader2 className="animate-spin text-cyan-400" size={32} />
                  </div>
                ) : rulePreview ? (
                  <>
                    <div className="p-3 border-b border-gray-800 bg-gray-800/30">
                      <div className="flex items-center justify-between">
                        <h3 className="font-medium text-white truncate">{selectedRule}</h3>
                        <button
                          onClick={loadRuleToInput}
                          className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500 text-white text-sm font-medium rounded-lg hover:bg-cyan-600 transition-colors"
                        >
                          <ArrowRightLeft size={14} />
                          Use This Rule
                        </button>
                      </div>
                    </div>
                    <pre className="flex-1 p-4 text-sm text-gray-300 font-mono overflow-auto">
                      {rulePreview}
                    </pre>
                  </>
                ) : (
                  <div className="flex-1 flex flex-col items-center justify-center text-gray-500 p-8">
                    <FileCode size={48} className="mb-4 opacity-50" />
                    <p className="text-center">Select a .yml file to preview</p>
                    <p className="text-sm text-center mt-2">
                      Browse the SigmaHQ repository to find detection rules
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
