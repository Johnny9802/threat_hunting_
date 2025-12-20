import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Save,
  X,
  Shield,
  AlertTriangle,
  FileCode,
  Tag,
  Target,
  Search,
  Loader2,
  CheckCircle,
  AlertCircle,
  Plus,
  Trash2,
} from 'lucide-react';
import { createPlaybook, updatePlaybook } from '../services/api';
import type { Playbook } from '../types/playbook';
import { cn } from '../lib/utils';

interface PlaybookFormProps {
  existingPlaybook?: Playbook;
  onClose?: () => void;
}

const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

export default function PlaybookForm({ existingPlaybook, onClose }: PlaybookFormProps) {
  const navigate = useNavigate();
  const isEdit = !!existingPlaybook;

  // Form state
  const [formData, setFormData] = useState({
    id: existingPlaybook?.id || '',
    name: existingPlaybook?.name || '',
    description: existingPlaybook?.description || '',
    technique: existingPlaybook?.mitre?.technique || '',
    tactic: existingPlaybook?.mitre?.tactic || '',
    subtechniques: existingPlaybook?.mitre?.subtechniques?.join(', ') || '',
    severity: existingPlaybook?.severity || 'medium',
    author: existingPlaybook?.author || '',
    data_sources: existingPlaybook?.data_sources?.join('\n') || '',
    hunt_hypothesis: existingPlaybook?.hunt_hypothesis || '',
    investigation_steps: existingPlaybook?.investigation_steps?.join('\n') || '',
    false_positives: existingPlaybook?.false_positives?.join('\n') || '',
    references: existingPlaybook?.references?.join('\n') || '',
    tags: existingPlaybook?.tags?.join(', ') || '',
    queries_splunk: existingPlaybook?.queries_content?.splunk || '',
    queries_elastic: existingPlaybook?.queries_content?.elastic || '',
    queries_sigma: existingPlaybook?.queries_content?.sigma || '',
  });

  const [iocs, setIocs] = useState(existingPlaybook?.iocs || []);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const playbookData: Partial<Playbook> = {
        id: formData.id,
        name: formData.name,
        description: formData.description,
        mitre: {
          technique: formData.technique,
          tactic: formData.tactic,
          subtechniques: formData.subtechniques
            ? formData.subtechniques.split(',').map((s) => s.trim()).filter(Boolean)
            : [],
        },
        severity: formData.severity as 'critical' | 'high' | 'medium' | 'low',
        author: formData.author,
        data_sources: formData.data_sources
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        hunt_hypothesis: formData.hunt_hypothesis,
        investigation_steps: formData.investigation_steps
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        false_positives: formData.false_positives
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        references: formData.references
          .split('\n')
          .map((s) => s.trim())
          .filter(Boolean),
        tags: formData.tags
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
        queries_content: {
          splunk: formData.queries_splunk,
          elastic: formData.queries_elastic,
          sigma: formData.queries_sigma,
        },
        iocs,
      };

      if (isEdit) {
        await updatePlaybook(formData.id, playbookData);
      } else {
        await createPlaybook(playbookData);
      }

      setSuccess(true);
      setTimeout(() => {
        if (onClose) {
          onClose();
        } else {
          navigate(`/playbook/${formData.id}`);
        }
      }, 1500);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to save playbook');
    } finally {
      setIsLoading(false);
    }
  };

  const addIOC = () => {
    setIocs([...iocs, { type: 'hash', value: '', context: '' }]);
  };

  const removeIOC = (index: number) => {
    setIocs(iocs.filter((_, i) => i !== index));
  };

  const updateIOC = (index: number, field: string, value: string) => {
    const newIOCs = [...iocs];
    newIOCs[index] = { ...newIOCs[index], [field]: value };
    setIocs(newIOCs);
  };

  return (
    <div className="min-h-screen bg-gray-950 p-6">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="rounded-lg bg-cyan-500/10 p-3">
              <Shield className="h-6 w-6 text-cyan-500" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-100">
                {isEdit ? 'Edit Playbook' : 'Create New Playbook'}
              </h1>
              <p className="text-sm text-gray-400">
                {isEdit ? 'Update playbook details' : 'Add a new threat hunting playbook'}
              </p>
            </div>
          </div>
          {onClose && (
            <button
              onClick={onClose}
              className="rounded-md p-2 text-gray-400 hover:bg-gray-800 hover:text-gray-100 transition-colors"
            >
              <X size={20} />
            </button>
          )}
        </div>

        {/* Success Message */}
        {success && (
          <div className="mb-6 rounded-lg border border-green-500/20 bg-green-500/10 p-4">
            <div className="flex items-center gap-3">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <p className="text-green-400">
                Playbook {isEdit ? 'updated' : 'created'} successfully!
              </p>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="mb-6 rounded-lg border border-red-500/20 bg-red-500/10 p-4">
            <div className="flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-400 font-medium">Error</p>
                <p className="text-sm text-red-300/80 mt-1">{error}</p>
              </div>
            </div>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Basic Info */}
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <h2 className="text-lg font-semibold text-gray-100 mb-4">Basic Information</h2>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Playbook ID *
                  </label>
                  <input
                    type="text"
                    required
                    disabled={isEdit}
                    value={formData.id}
                    onChange={(e) => setFormData({ ...formData, id: e.target.value })}
                    placeholder="PB-T1566-001"
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed"
                  />
                  <p className="text-xs text-gray-500 mt-1">Format: PB-TXXXX-NNN</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Author *
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.author}
                    onChange={(e) => setFormData({ ...formData, author: e.target.value })}
                    placeholder="Threat Hunting Team"
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Playbook Name *
                </label>
                <input
                  type="text"
                  required
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="Phishing Email Detection and Analysis"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Description *
                </label>
                <textarea
                  required
                  rows={3}
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  placeholder="Detect and investigate phishing emails..."
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK */}
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <div className="flex items-center gap-2 mb-4">
              <Target className="h-5 w-5 text-cyan-500" />
              <h2 className="text-lg font-semibold text-gray-100">MITRE ATT&CK Mapping</h2>
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Technique ID *
                  </label>
                  <input
                    type="text"
                    required
                    value={formData.technique}
                    onChange={(e) => setFormData({ ...formData, technique: e.target.value })}
                    placeholder="T1566"
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Tactic *
                  </label>
                  <select
                    required
                    value={formData.tactic}
                    onChange={(e) => setFormData({ ...formData, tactic: e.target.value })}
                    className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                  >
                    <option value="">Select tactic</option>
                    {MITRE_TACTICS.map((tactic) => (
                      <option key={tactic.id} value={tactic.name}>
                        {tactic.name} ({tactic.id})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Sub-techniques
                </label>
                <input
                  type="text"
                  value={formData.subtechniques}
                  onChange={(e) => setFormData({ ...formData, subtechniques: e.target.value })}
                  placeholder="T1566.001, T1566.002"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-xs text-gray-500 mt-1">Comma-separated list</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Severity *
                </label>
                <div className="grid grid-cols-4 gap-2">
                  {(['low', 'medium', 'high', 'critical'] as const).map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => setFormData({ ...formData, severity: sev })}
                      className={cn(
                        'rounded-lg px-4 py-2 text-sm font-medium transition-colors',
                        formData.severity === sev
                          ? sev === 'critical'
                            ? 'bg-red-500 text-white'
                            : sev === 'high'
                            ? 'bg-orange-500 text-white'
                            : sev === 'medium'
                            ? 'bg-yellow-500 text-gray-900'
                            : 'bg-blue-500 text-white'
                          : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      )}
                    >
                      {sev.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Hunt Details */}
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <div className="flex items-center gap-2 mb-4">
              <Search className="h-5 w-5 text-cyan-500" />
              <h2 className="text-lg font-semibold text-gray-100">Hunt Details</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Hunt Hypothesis *
                </label>
                <textarea
                  required
                  rows={5}
                  value={formData.hunt_hypothesis}
                  onChange={(e) => setFormData({ ...formData, hunt_hypothesis: e.target.value })}
                  placeholder="Adversaries frequently use phishing as an initial access vector..."
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Data Sources
                </label>
                <textarea
                  rows={4}
                  value={formData.data_sources}
                  onChange={(e) => setFormData({ ...formData, data_sources: e.target.value })}
                  placeholder="Email Gateway Logs&#10;Web Proxy Logs&#10;Endpoint Detection"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
                <p className="text-xs text-gray-500 mt-1">One per line</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Investigation Steps
                </label>
                <textarea
                  rows={6}
                  value={formData.investigation_steps}
                  onChange={(e) => setFormData({ ...formData, investigation_steps: e.target.value })}
                  placeholder="Check sender reputation&#10;Analyze email headers&#10;Extract and detonate attachments"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
                <p className="text-xs text-gray-500 mt-1">One per line</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  False Positives
                </label>
                <textarea
                  rows={4}
                  value={formData.false_positives}
                  onChange={(e) => setFormData({ ...formData, false_positives: e.target.value })}
                  placeholder="Legitimate marketing emails&#10;Automated notifications&#10;Newsletter subscriptions"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
                <p className="text-xs text-gray-500 mt-1">One per line</p>
              </div>
            </div>
          </div>

          {/* Detection Queries */}
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <div className="flex items-center gap-2 mb-4">
              <FileCode className="h-5 w-5 text-cyan-500" />
              <h2 className="text-lg font-semibold text-gray-100">Detection Queries</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Splunk SPL Query
                </label>
                <textarea
                  rows={6}
                  value={formData.queries_splunk}
                  onChange={(e) => setFormData({ ...formData, queries_splunk: e.target.value })}
                  placeholder="index=email sourcetype=proofpoint&#10;| search subject=*invoice* OR subject=*urgent*"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none font-mono text-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Elastic KQL Query
                </label>
                <textarea
                  rows={6}
                  value={formData.queries_elastic}
                  onChange={(e) => setFormData({ ...formData, queries_elastic: e.target.value })}
                  placeholder="event.category:email and (email.subject:*invoice* or email.subject:*urgent*)"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none font-mono text-sm"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Sigma Rule
                </label>
                <textarea
                  rows={8}
                  value={formData.queries_sigma}
                  onChange={(e) => setFormData({ ...formData, queries_sigma: e.target.value })}
                  placeholder="title: Suspicious Email&#10;detection:&#10;  selection:&#10;    category: email"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none font-mono text-sm"
                />
              </div>
            </div>
          </div>

          {/* IOCs */}
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-cyan-500" />
                <h2 className="text-lg font-semibold text-gray-100">Indicators of Compromise</h2>
              </div>
              <button
                type="button"
                onClick={addIOC}
                className="flex items-center gap-2 rounded-lg bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-400 hover:bg-cyan-500/20 transition-colors"
              >
                <Plus size={16} />
                Add IOC
              </button>
            </div>
            <div className="space-y-3">
              {iocs.map((ioc, index) => (
                <div key={index} className="grid grid-cols-12 gap-3">
                  <div className="col-span-3">
                    <select
                      value={ioc.type}
                      onChange={(e) => updateIOC(index, 'type', e.target.value)}
                      className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    >
                      <option value="hash">Hash</option>
                      <option value="domain">Domain</option>
                      <option value="ip">IP Address</option>
                      <option value="url">URL</option>
                      <option value="email">Email</option>
                    </select>
                  </div>
                  <div className="col-span-4">
                    <input
                      type="text"
                      value={ioc.value}
                      onChange={(e) => updateIOC(index, 'value', e.target.value)}
                      placeholder="IOC value"
                      className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                  <div className="col-span-4">
                    <input
                      type="text"
                      value={ioc.context}
                      onChange={(e) => updateIOC(index, 'context', e.target.value)}
                      placeholder="Context"
                      className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                    />
                  </div>
                  <div className="col-span-1">
                    <button
                      type="button"
                      onClick={() => removeIOC(index)}
                      className="w-full rounded-lg bg-red-500/10 px-3 py-2 text-red-400 hover:bg-red-500/20 transition-colors"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Metadata */}
          <div className="rounded-lg border border-gray-800 bg-gray-900 p-6">
            <div className="flex items-center gap-2 mb-4">
              <Tag className="h-5 w-5 text-cyan-500" />
              <h2 className="text-lg font-semibold text-gray-100">Metadata</h2>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Tags
                </label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  placeholder="phishing, email, initial-access"
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
                <p className="text-xs text-gray-500 mt-1">Comma-separated list</p>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  References
                </label>
                <textarea
                  rows={4}
                  value={formData.references}
                  onChange={(e) => setFormData({ ...formData, references: e.target.value })}
                  placeholder="https://attack.mitre.org/techniques/T1566/&#10;https://..."
                  className="w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-gray-100 placeholder-gray-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 resize-none"
                />
                <p className="text-xs text-gray-500 mt-1">One per line</p>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center justify-end gap-3">
            {onClose && (
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-gray-800 bg-gray-900 px-6 py-2.5 text-sm font-medium text-gray-300 hover:bg-gray-800 transition-colors"
              >
                Cancel
              </button>
            )}
            <button
              type="submit"
              disabled={isLoading}
              className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-6 py-2.5 text-sm font-medium text-white hover:from-cyan-600 hover:to-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {isEdit ? 'Updating...' : 'Creating...'}
                </>
              ) : (
                <>
                  <Save className="h-4 w-4" />
                  {isEdit ? 'Update Playbook' : 'Create Playbook'}
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
