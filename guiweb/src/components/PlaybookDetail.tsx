import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Calendar,
  User,
  Database,
  FileCode,
  AlertCircle,
  CheckCircle,
  Copy,
  Download,
  ExternalLink,
  Loader2,
  Tag,
  ListChecks,
  Search,
  Lightbulb,
  Info,
} from 'lucide-react';
import { usePlaybook } from '../hooks/usePlaybooks';
import { cn, getSeverityBadgeColor, formatDate, copyToClipboard, downloadText } from '../lib/utils';
import type { Playbook, IOC } from '../types/playbook';

type TabType = 'overview' | 'queries' | 'iocs' | 'response';

const tabs: { id: TabType; label: string; icon: typeof Shield }[] = [
  { id: 'overview', label: 'Overview', icon: Shield },
  { id: 'queries', label: 'Queries', icon: FileCode },
  { id: 'iocs', label: 'IOCs', icon: AlertCircle },
  { id: 'response', label: 'Response', icon: AlertTriangle },
];

export default function PlaybookDetail() {
  const { id } = useParams<{ id: string }>();
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [copiedQuery, setCopiedQuery] = useState<string | null>(null);

  const { data: playbook, isLoading, error, isError } = usePlaybook(id || '');

  const handleCopy = async (text: string, type: string) => {
    try {
      await copyToClipboard(text);
      setCopiedQuery(type);
      setTimeout(() => setCopiedQuery(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const handleDownload = (text: string, filename: string) => {
    downloadText(text, filename);
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-10 w-10 animate-spin text-cyan-500" />
          <p className="text-gray-400">Loading playbook...</p>
        </div>
      </div>
    );
  }

  if (isError || !playbook) {
    return (
      <div className="space-y-4">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
        >
          <ArrowLeft size={16} />
          Back to playbooks
        </Link>
        <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-6">
          <div className="flex items-start gap-3">
            <AlertCircle className="h-6 w-6 text-red-500 flex-shrink-0 mt-0.5" />
            <div>
              <h3 className="text-lg font-semibold text-red-400">Failed to load playbook</h3>
              <p className="text-sm text-red-300/80 mt-1">
                {error instanceof Error ? error.message : 'Playbook not found'}
              </p>
              <Link
                to="/"
                className="mt-3 inline-block rounded-md bg-red-500/20 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-500/30 transition-colors"
              >
                Return to playbooks
              </Link>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <Link
        to="/"
        className="inline-flex items-center gap-2 text-sm text-gray-400 hover:text-gray-200 transition-colors"
      >
        <ArrowLeft size={16} />
        Back to playbooks
      </Link>

      {/* Header */}
      <div className="space-y-4">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-4">
            <div className="rounded-lg bg-cyan-500/10 p-3 border border-cyan-500/20">
              <Shield className="h-8 w-8 text-cyan-500" />
            </div>
            <div className="flex-1">
              <h1 className="text-3xl font-bold text-gray-100">{playbook.name}</h1>
              <p className="text-gray-400 mt-2">{playbook.description}</p>
            </div>
          </div>
          <span
            className={cn(
              'inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-sm font-semibold',
              getSeverityBadgeColor(playbook.severity)
            )}
          >
            <AlertTriangle size={16} />
            {playbook.severity.toUpperCase()}
          </span>
        </div>

        {/* Metadata */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <MetadataCard
            icon={User}
            label="Author"
            value={playbook.author}
          />
          <MetadataCard
            icon={Calendar}
            label="Created"
            value={formatDate(playbook.created)}
          />
          <MetadataCard
            icon={Calendar}
            label="Updated"
            value={formatDate(playbook.updated)}
          />
          <MetadataCard
            icon={Shield}
            label="MITRE Technique"
            value={playbook.mitre?.technique || 'N/A'}
          />
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-800">
        <nav className="flex gap-6">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  'flex items-center gap-2 border-b-2 px-1 py-3 text-sm font-medium transition-colors',
                  isActive
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                )}
              >
                <Icon size={18} />
                {tab.label}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="pb-8">
        {activeTab === 'overview' && <OverviewTab playbook={playbook} />}
        {activeTab === 'queries' && (
          <QueriesTab
            playbook={playbook}
            onCopy={handleCopy}
            onDownload={handleDownload}
            copiedQuery={copiedQuery}
          />
        )}
        {activeTab === 'iocs' && <IOCsTab playbook={playbook} />}
        {activeTab === 'response' && <ResponseTab playbook={playbook} />}
      </div>
    </div>
  );
}

// Metadata Card Component
interface MetadataCardProps {
  icon: typeof Shield;
  label: string;
  value: string;
}

function MetadataCard({ icon: Icon, label, value }: MetadataCardProps) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <div className="flex items-center gap-2 text-sm text-gray-400 mb-1">
        <Icon size={16} />
        {label}
      </div>
      <p className="font-medium text-gray-100">{value}</p>
    </div>
  );
}

// Overview Tab
function OverviewTab({ playbook }: { playbook: Playbook }) {
  return (
    <div className="space-y-6">
      {/* MITRE ATT&CK Info */}
      <Section title="MITRE ATT&CK Framework" icon={Shield}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <InfoItem label="Tactic" value={playbook.mitre?.tactic || playbook.tactic || 'N/A'} />
          <InfoItem label="Technique" value={playbook.mitre?.technique || 'N/A'} />
          {playbook.mitre?.subtechniques && playbook.mitre.subtechniques.length > 0 && (
            <div className="md:col-span-2">
              <InfoItem
                label="Subtechniques"
                value={playbook.mitre.subtechniques.join(', ')}
              />
            </div>
          )}
        </div>
      </Section>

      {/* Hunt Hypothesis */}
      <Section title="Hunt Hypothesis" icon={Lightbulb}>
        <p className="text-gray-300 leading-relaxed">{playbook.hunt_hypothesis}</p>
      </Section>

      {/* Data Sources */}
      <Section title="Data Sources" icon={Database}>
        <div className="flex flex-wrap gap-2">
          {playbook.data_sources?.map((source) => (
            <span
              key={source}
              className="inline-flex items-center gap-1.5 rounded-lg bg-gray-800 px-3 py-1.5 text-sm text-gray-300"
            >
              <Database size={14} className="text-gray-500" />
              {source}
            </span>
          ))}
        </div>
      </Section>

      {/* Investigation Steps */}
      <Section title="Investigation Steps" icon={ListChecks}>
        <ol className="space-y-2">
          {playbook.investigation_steps?.map((step, index) => (
            <li key={index} className="flex items-start gap-3">
              <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                {index + 1}
              </span>
              <span className="text-gray-300 leading-relaxed">{step}</span>
            </li>
          ))}
        </ol>
      </Section>

      {/* False Positives */}
      <Section title="False Positives" icon={AlertCircle}>
        <ul className="space-y-2">
          {playbook.false_positives?.map((fp, index) => (
            <li key={index} className="flex items-start gap-3 text-gray-300">
              <AlertTriangle size={16} className="text-yellow-500 flex-shrink-0 mt-0.5" />
              <span>{fp}</span>
            </li>
          ))}
        </ul>
      </Section>

      {/* Tags */}
      {playbook.tags && playbook.tags.length > 0 && (
        <Section title="Tags" icon={Tag}>
          <div className="flex flex-wrap gap-2">
            {playbook.tags.map((tag) => (
              <span
                key={tag}
                className="inline-flex items-center gap-1.5 rounded-full bg-gray-800 px-3 py-1.5 text-sm text-gray-300"
              >
                <Tag size={14} className="text-gray-500" />
                {tag}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* References */}
      {playbook.references && playbook.references.length > 0 && (
        <Section title="References" icon={ExternalLink}>
          <ul className="space-y-2">
            {playbook.references.map((ref, index) => (
              <li key={index}>
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <ExternalLink size={14} />
                  <span className="break-all">{ref}</span>
                </a>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

// Queries Tab
interface QueriesTabProps {
  playbook: Playbook;
  onCopy: (text: string, type: string) => void;
  onDownload: (text: string, filename: string) => void;
  copiedQuery: string | null;
}

function QueriesTab({ playbook, onCopy, onDownload, copiedQuery }: QueriesTabProps) {
  const queries = [
    { type: 'splunk', label: 'Splunk', query: playbook.queries_content?.splunk },
    { type: 'elastic', label: 'Elastic', query: playbook.queries_content?.elastic },
    { type: 'sigma', label: 'Sigma', query: playbook.queries_content?.sigma },
  ].filter((q) => q.query);

  if (queries.length === 0) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-12 text-center">
        <FileCode className="h-12 w-12 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-400">No queries available for this playbook</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {queries.map(({ type, label, query }) => (
        <div key={type} className="rounded-lg border border-gray-800 bg-gray-900 overflow-hidden">
          <div className="flex items-center justify-between border-b border-gray-800 bg-gray-900/50 px-4 py-3">
            <div className="flex items-center gap-2">
              <FileCode size={18} className="text-cyan-500" />
              <h3 className="font-semibold text-gray-100">{label} Query</h3>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={() => onCopy(query || '', type)}
                className="flex items-center gap-1.5 rounded-md bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 transition-colors"
                aria-label={`Copy ${label} query`}
              >
                {copiedQuery === type ? (
                  <>
                    <CheckCircle size={14} className="text-green-500" />
                    Copied
                  </>
                ) : (
                  <>
                    <Copy size={14} />
                    Copy
                  </>
                )}
              </button>
              <button
                onClick={() => onDownload(query || '', `${playbook.id}-${type}.txt`)}
                className="flex items-center gap-1.5 rounded-md bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 transition-colors"
                aria-label={`Download ${label} query`}
              >
                <Download size={14} />
                Download
              </button>
            </div>
          </div>
          <pre className="overflow-x-auto p-4 text-sm text-gray-300">
            <code>{query}</code>
          </pre>
        </div>
      ))}
    </div>
  );
}

// IOCs Tab
function IOCsTab({ playbook }: { playbook: Playbook }) {
  const [searchTerm, setSearchTerm] = useState('');

  const filteredIOCs = playbook.iocs?.filter(
    (ioc) =>
      ioc.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ioc.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      ioc.context.toLowerCase().includes(searchTerm.toLowerCase())
  );

  if (!playbook.iocs || playbook.iocs.length === 0) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-12 text-center">
        <AlertCircle className="h-12 w-12 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-400">No IOCs available for this playbook</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
        <input
          type="text"
          placeholder="Search IOCs by value, type, or context..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full rounded-lg border border-gray-800 bg-gray-900 pl-10 pr-4 py-3 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-colors"
        />
      </div>

      {/* IOCs Table */}
      <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-900">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="border-b border-gray-800 bg-gray-900/50">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                  Value
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-400">
                  Context
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium uppercase tracking-wider text-gray-400">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {filteredIOCs && filteredIOCs.length > 0 ? (
                filteredIOCs.map((ioc, index) => (
                  <IOCRow key={index} ioc={ioc} />
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-gray-400">
                    No IOCs match your search
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// IOC Row Component
function IOCRow({ ioc }: { ioc: IOC }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await copyToClipboard(ioc.value);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const getTypeColor = (type: string) => {
    const colors: Record<string, string> = {
      ip: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      domain: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      url: 'bg-green-500/10 text-green-400 border-green-500/20',
      hash: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      email: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
    };
    return colors[type.toLowerCase()] || 'bg-gray-500/10 text-gray-400 border-gray-500/20';
  };

  return (
    <tr className="hover:bg-gray-800/50 transition-colors">
      <td className="px-6 py-4">
        <span
          className={cn(
            'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold',
            getTypeColor(ioc.type)
          )}
        >
          {ioc.type.toUpperCase()}
        </span>
      </td>
      <td className="px-6 py-4">
        <code className="text-sm text-gray-300 bg-gray-800 px-2 py-1 rounded">
          {ioc.value}
        </code>
      </td>
      <td className="px-6 py-4 text-sm text-gray-400">{ioc.context}</td>
      <td className="px-6 py-4 text-right">
        <button
          onClick={handleCopy}
          className="inline-flex items-center gap-1.5 rounded-md bg-gray-800 px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 transition-colors"
          aria-label="Copy IOC value"
        >
          {copied ? (
            <>
              <CheckCircle size={14} className="text-green-500" />
              Copied
            </>
          ) : (
            <>
              <Copy size={14} />
              Copy
            </>
          )}
        </button>
      </td>
    </tr>
  );
}

// Section Component
interface SectionProps {
  title: string;
  icon: typeof Shield;
  children: React.ReactNode;
}

function Section({ title, icon: Icon, children }: SectionProps) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
      <div className="flex items-center gap-2 mb-4">
        <Icon size={20} className="text-cyan-500" />
        <h2 className="text-xl font-semibold text-gray-100">{title}</h2>
      </div>
      {children}
    </div>
  );
}

// Info Item Component
function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-sm text-gray-400 mb-1">{label}</p>
      <p className="font-medium text-gray-100">{value}</p>
    </div>
  );
}

// Response Tab
function ResponseTab({ playbook }: { playbook: Playbook }) {
  if (!playbook.response) {
    return (
      <div className="rounded-lg border border-gray-800 bg-gray-900 p-12 text-center">
        <AlertTriangle className="h-12 w-12 text-gray-600 mx-auto mb-3" />
        <p className="text-gray-400">No response actions defined for this playbook</p>
        <p className="text-sm text-gray-500 mt-1">
          Response actions will be added as the playbook evolves
        </p>
      </div>
    );
  }

  const sections = [
    {
      key: 'quick_wins',
      title: 'Quick Wins',
      description: 'Immediate actions for rapid risk reduction',
      icon: Lightbulb,
      color: 'text-yellow-500',
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/20',
      data: playbook.response.quick_wins,
    },
    {
      key: 'containment',
      title: 'Containment',
      description: 'Actions to prevent spread and limit impact',
      icon: Shield,
      color: 'text-cyan-500',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/20',
      data: playbook.response.containment,
    },
    {
      key: 'eradication',
      title: 'Eradication',
      description: 'Steps to remove the threat completely',
      icon: AlertCircle,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20',
      data: playbook.response.eradication,
    },
    {
      key: 'recovery',
      title: 'Recovery',
      description: 'Restoration and return to normal operations',
      icon: CheckCircle,
      color: 'text-green-500',
      bgColor: 'bg-green-500/10',
      borderColor: 'border-green-500/20',
      data: playbook.response.recovery,
    },
  ];

  return (
    <div className="space-y-6">
      {/* Info Banner */}
      <div className="rounded-lg border border-blue-500/20 bg-blue-500/10 p-4">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm text-blue-300 font-medium">
              NIST Incident Response Framework
            </p>
            <p className="text-xs text-blue-200/80 mt-1">
              These response actions follow the NIST incident response lifecycle: Preparation,
              Detection & Analysis, Containment/Eradication/Recovery, and Post-Incident Activity.
              Severity: <strong>{playbook.severity.toUpperCase()}</strong>
            </p>
          </div>
        </div>
      </div>

      {/* Response Sections */}
      {sections.map((section) => {
        if (!section.data || section.data.length === 0) return null;

        const Icon = section.icon;

        return (
          <div
            key={section.key}
            className={cn(
              'rounded-lg border bg-gray-900 p-6',
              section.borderColor
            )}
          >
            <div className="flex items-start gap-3 mb-4">
              <div className={cn('rounded-lg p-2', section.bgColor)}>
                <Icon className={cn('h-5 w-5', section.color)} />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-gray-100">{section.title}</h3>
                <p className="text-sm text-gray-400 mt-0.5">{section.description}</p>
              </div>
            </div>
            <ul className="space-y-2 ml-11">
              {section.data.map((item, index) => (
                <li key={index} className="flex items-start gap-3">
                  <span className="flex-shrink-0 flex items-center justify-center w-6 h-6 rounded-full bg-gray-800 text-gray-400 text-xs font-semibold mt-0.5">
                    {index + 1}
                  </span>
                  <span className="text-gray-300 leading-relaxed">{item}</span>
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
}
