import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield,
  AlertTriangle,
  Activity,
  TrendingUp,
  Database,
  FileCode,
  Target,
  Loader2,
  AlertCircle,
  BarChart3,
  PieChart,
  Calendar,
} from 'lucide-react';
import { usePlaybooks } from '../hooks/usePlaybooks';
import { cn, getSeverityBadgeColor, formatDate } from '../lib/utils';

export default function Dashboard() {
  const { data: playbooks, isLoading, isError, error } = usePlaybooks();

  // Calculate statistics
  const stats = useMemo(() => {
    if (!playbooks) return null;

    const totalPlaybooks = playbooks.length;

    // Severity distribution
    const severityCount = playbooks.reduce((acc, pb) => {
      acc[pb.severity] = (acc[pb.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // MITRE Tactic distribution
    const tacticCount = playbooks.reduce((acc, pb) => {
      const tactic = pb.mitre?.tactic || pb.tactic || 'Unknown';
      acc[tactic] = (acc[tactic] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    // MITRE Technique coverage
    const techniques = new Set(
      playbooks
        .map((pb) => pb.mitre?.technique)
        .filter((t): t is string => !!t)
    );

    // Data source distribution
    const dataSourceCount = playbooks.reduce((acc, pb) => {
      pb.data_sources?.forEach((source) => {
        acc[source] = (acc[source] || 0) + 1;
      });
      return acc;
    }, {} as Record<string, number>);

    // Recent playbooks
    const recentPlaybooks = [...playbooks]
      .sort((a, b) => new Date(b.updated).getTime() - new Date(a.updated).getTime())
      .slice(0, 5);

    // Top tactics
    const topTactics = Object.entries(tacticCount)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);

    // Top data sources
    const topDataSources = Object.entries(dataSourceCount)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);

    return {
      totalPlaybooks,
      severityCount,
      tacticCount,
      techniques: techniques.size,
      recentPlaybooks,
      topTactics,
      topDataSources,
    };
  }, [playbooks]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="h-10 w-10 animate-spin text-cyan-500" />
          <p className="text-gray-400">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  if (isError || !stats) {
    return (
      <div className="rounded-lg border border-red-500/20 bg-red-500/10 p-6">
        <div className="flex items-start gap-3">
          <AlertCircle className="h-6 w-6 text-red-500 flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="text-lg font-semibold text-red-400">Failed to load dashboard</h3>
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
      <div>
        <h1 className="text-3xl font-bold text-gray-100">Dashboard</h1>
        <p className="text-gray-400 mt-1">Overview of your threat hunting playbooks</p>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          icon={Shield}
          label="Total Playbooks"
          value={stats.totalPlaybooks.toString()}
          color="cyan"
        />
        <MetricCard
          icon={Target}
          label="MITRE Techniques"
          value={stats.techniques.toString()}
          color="blue"
        />
        <MetricCard
          icon={AlertTriangle}
          label="Critical Severity"
          value={stats.severityCount.critical || 0}
          color="red"
        />
        <MetricCard
          icon={Activity}
          label="Coverage"
          value={`${Math.round((stats.techniques / 193) * 100)}%`}
          color="green"
          subtitle="of ATT&CK Enterprise"
        />
      </div>

      {/* Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center gap-2 mb-4">
            <PieChart className="h-5 w-5 text-cyan-500" />
            <h2 className="text-xl font-semibold text-gray-100">Severity Distribution</h2>
          </div>
          <div className="space-y-3">
            {['critical', 'high', 'medium', 'low'].map((severity) => {
              const count = stats.severityCount[severity] || 0;
              const percentage = Math.round((count / stats.totalPlaybooks) * 100);

              return (
                <div key={severity}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium text-gray-300 capitalize">
                      {severity}
                    </span>
                    <span className="text-sm text-gray-400">
                      {count} ({percentage}%)
                    </span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full transition-all',
                        severity === 'critical' && 'bg-red-500',
                        severity === 'high' && 'bg-orange-500',
                        severity === 'medium' && 'bg-yellow-500',
                        severity === 'low' && 'bg-blue-500'
                      )}
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top MITRE Tactics */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="h-5 w-5 text-cyan-500" />
            <h2 className="text-xl font-semibold text-gray-100">Top MITRE Tactics</h2>
          </div>
          <div className="space-y-3">
            {stats.topTactics.map(([tactic, count], index) => {
              const percentage = Math.round((count / stats.totalPlaybooks) * 100);

              return (
                <div key={tactic}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="flex items-center justify-center w-5 h-5 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                        {index + 1}
                      </span>
                      <span className="text-sm font-medium text-gray-300 truncate">
                        {tactic}
                      </span>
                    </div>
                    <span className="text-sm text-gray-400">
                      {count} ({percentage}%)
                    </span>
                  </div>
                  <div className="h-2 bg-gray-800 rounded-full overflow-hidden ml-7">
                    <div
                      className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all"
                      style={{ width: `${percentage}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Recent Playbooks & Top Data Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Playbooks */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center gap-2 mb-4">
            <TrendingUp className="h-5 w-5 text-cyan-500" />
            <h2 className="text-xl font-semibold text-gray-100">Recent Playbooks</h2>
          </div>
          <div className="space-y-3">
            {stats.recentPlaybooks.map((playbook) => (
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
                    <p className="text-xs text-gray-500 mt-1 flex items-center gap-1">
                      <Calendar size={12} />
                      Updated {formatDate(playbook.updated)}
                    </p>
                  </div>
                  <span
                    className={cn(
                      'inline-flex items-center rounded-full px-2 py-0.5 text-xs font-semibold flex-shrink-0',
                      getSeverityBadgeColor(playbook.severity)
                    )}
                  >
                    {playbook.severity.toUpperCase()}
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>

        {/* Top Data Sources */}
        <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center gap-2 mb-4">
            <Database className="h-5 w-5 text-cyan-500" />
            <h2 className="text-xl font-semibold text-gray-100">Top Data Sources</h2>
          </div>
          <div className="space-y-3">
            {stats.topDataSources.map(([source, count], index) => (
              <div
                key={source}
                className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-950 p-3"
              >
                <div className="flex items-center gap-3">
                  <span className="flex items-center justify-center w-6 h-6 rounded-full bg-cyan-500/10 text-cyan-400 text-xs font-semibold">
                    {index + 1}
                  </span>
                  <div className="flex items-center gap-2">
                    <FileCode size={16} className="text-gray-500" />
                    <span className="text-sm font-medium text-gray-300">{source}</span>
                  </div>
                </div>
                <span className="rounded-full bg-gray-800 px-3 py-1 text-xs font-semibold text-gray-400">
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// Metric Card Component
interface MetricCardProps {
  icon: typeof Shield;
  label: string;
  value: string | number;
  color: 'cyan' | 'blue' | 'red' | 'green';
  subtitle?: string;
}

function MetricCard({ icon: Icon, label, value, color, subtitle }: MetricCardProps) {
  const colorClasses = {
    cyan: 'from-cyan-500 to-cyan-600',
    blue: 'from-blue-500 to-blue-600',
    red: 'from-red-500 to-red-600',
    green: 'from-green-500 to-green-600',
  };

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-gray-400 mb-1">{label}</p>
          <p className="text-3xl font-bold text-gray-100">{value}</p>
          {subtitle && <p className="text-xs text-gray-500 mt-1">{subtitle}</p>}
        </div>
        <div className={cn('rounded-lg bg-gradient-to-br p-3', colorClasses[color])}>
          <Icon className="h-6 w-6 text-white" />
        </div>
      </div>
    </div>
  );
}
