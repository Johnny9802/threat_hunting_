import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Settings,
  Plus,
  Trash2,
  Edit2,
  Save,
  X,
  Upload,
  Download,
  FileCode,
  Shield,
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  Database,
  Loader2,
  Info,
} from 'lucide-react';
import { cn } from '../lib/utils';
import {
  listProfiles,
  createProfile,
  updateProfile,
  deleteProfile,
  getProfileMappings,
  addMapping,
  bulkUpdateMappings,
  deleteMapping,
  type SigmaProfile,
  type FieldMapping,
} from '../services/sigmaApi';

interface SysmonConfig {
  version: string;
  schemaVersion: string;
  enabledEventIds: number[];
  disabledEventIds: number[];
  rules: { eventId: number; name: string; enabled: boolean }[];
}

interface WindowsAuditPolicy {
  categories: { name: string; subcategories: { name: string; success: boolean; failure: boolean }[] }[];
}

interface GapAnalysisResult {
  passed: boolean;
  missingEventIds: number[];
  missingAuditPolicies: string[];
  recommendations: string[];
}

export default function SigmaMappings() {
  const queryClient = useQueryClient();
  const [selectedProfileId, setSelectedProfileId] = useState<number | null>(null);
  const [isCreatingProfile, setIsCreatingProfile] = useState(false);
  const [editingProfile, setEditingProfile] = useState<SigmaProfile | null>(null);
  const [newProfileName, setNewProfileName] = useState('');
  const [newProfileIndex, setNewProfileIndex] = useState('');
  const [newProfileSourcetype, setNewProfileSourcetype] = useState('');
  const [editingMapping, setEditingMapping] = useState<FieldMapping | null>(null);
  const [newMapping, setNewMapping] = useState({ sigma_field: '', target_field: '', transform: '' });
  const [isAddingMapping, setIsAddingMapping] = useState(false);
  const [activeTab, setActiveTab] = useState<'mappings' | 'sysmon' | 'audit'>('mappings');

  // Sysmon and Audit Policy states
  const [sysmonConfig, setSysmonConfig] = useState<SysmonConfig | null>(null);
  const [auditPolicy, setAuditPolicy] = useState<WindowsAuditPolicy | null>(null);
  const [gapAnalysis, setGapAnalysis] = useState<GapAnalysisResult | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Fetch profiles
  const { data: profiles = [], isLoading: loadingProfiles } = useQuery({
    queryKey: ['sigma-profiles'],
    queryFn: listProfiles,
  });

  // Fetch mappings for selected profile
  const { data: mappings = [], isLoading: loadingMappings } = useQuery({
    queryKey: ['sigma-mappings', selectedProfileId],
    queryFn: () => selectedProfileId ? getProfileMappings(selectedProfileId) : Promise.resolve([]),
    enabled: !!selectedProfileId,
  });

  // Create profile mutation
  const createProfileMutation = useMutation({
    mutationFn: createProfile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sigma-profiles'] });
      setIsCreatingProfile(false);
      setNewProfileName('');
      setNewProfileIndex('');
      setNewProfileSourcetype('');
    },
  });

  // Update profile mutation
  const updateProfileMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<SigmaProfile> }) =>
      updateProfile(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sigma-profiles'] });
      setEditingProfile(null);
    },
  });

  // Delete profile mutation
  const deleteProfileMutation = useMutation({
    mutationFn: deleteProfile,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sigma-profiles'] });
      if (selectedProfileId) setSelectedProfileId(null);
    },
  });

  // Add mapping mutation
  const addMappingMutation = useMutation({
    mutationFn: ({ profileId, mapping }: { profileId: number; mapping: typeof newMapping }) =>
      addMapping(profileId, mapping),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sigma-mappings', selectedProfileId] });
      setIsAddingMapping(false);
      setNewMapping({ sigma_field: '', target_field: '', transform: '' });
    },
  });

  // Delete mapping mutation
  const deleteMappingMutation = useMutation({
    mutationFn: ({ profileId, sigmaField }: { profileId: number; sigmaField: string }) =>
      deleteMapping(profileId, sigmaField),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sigma-mappings', selectedProfileId] });
    },
  });

  // Bulk update mappings mutation
  const bulkUpdateMutation = useMutation({
    mutationFn: ({ profileId, mappings }: { profileId: number; mappings: FieldMapping[] }) =>
      bulkUpdateMappings(profileId, mappings),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sigma-mappings', selectedProfileId] });
      setEditingMapping(null);
    },
  });

  // Parse Sysmon config XML
  const parseSysmonConfig = (xmlText: string): SysmonConfig | null => {
    try {
      const parser = new DOMParser();
      const doc = parser.parseFromString(xmlText, 'text/xml');

      const parseError = doc.querySelector('parsererror');
      if (parseError) {
        throw new Error('Invalid XML format');
      }

      const sysmonNode = doc.querySelector('Sysmon');
      const config: SysmonConfig = {
        version: sysmonNode?.getAttribute('schemaversion') || 'Unknown',
        schemaVersion: sysmonNode?.getAttribute('schemaversion') || 'Unknown',
        enabledEventIds: [],
        disabledEventIds: [],
        rules: [],
      };

      // Map of Sysmon Event IDs to names
      const eventIdMap: Record<number, string> = {
        1: 'ProcessCreate',
        2: 'FileCreateTime',
        3: 'NetworkConnect',
        4: 'SysmonServiceStateChange',
        5: 'ProcessTerminate',
        6: 'DriverLoad',
        7: 'ImageLoad',
        8: 'CreateRemoteThread',
        9: 'RawAccessRead',
        10: 'ProcessAccess',
        11: 'FileCreate',
        12: 'RegistryEvent (Object create and delete)',
        13: 'RegistryEvent (Value Set)',
        14: 'RegistryEvent (Key and Value Rename)',
        15: 'FileCreateStreamHash',
        16: 'ServiceConfigurationChange',
        17: 'PipeEvent (Pipe Created)',
        18: 'PipeEvent (Pipe Connected)',
        19: 'WmiEvent (WmiEventFilter activity)',
        20: 'WmiEvent (WmiEventConsumer activity)',
        21: 'WmiEvent (WmiEventConsumerToFilter activity)',
        22: 'DNSEvent',
        23: 'FileDelete (archived)',
        24: 'ClipboardChange',
        25: 'ProcessTampering',
        26: 'FileDeleteDetected',
        27: 'FileBlockExecutable',
        28: 'FileBlockShredding',
        29: 'FileExecutableDetected',
      };

      // Check for EventFiltering section
      const eventFiltering = doc.querySelector('EventFiltering');
      if (eventFiltering) {
        // Check each rule type
        Object.entries(eventIdMap).forEach(([idStr, name]) => {
          const id = parseInt(idStr);
          const ruleNode = eventFiltering.querySelector(name);

          if (ruleNode) {
            const onMatch = ruleNode.getAttribute('onmatch');
            const enabled = onMatch !== 'exclude' || ruleNode.children.length > 0;
            config.rules.push({ eventId: id, name, enabled });
            if (enabled) {
              config.enabledEventIds.push(id);
            } else {
              config.disabledEventIds.push(id);
            }
          } else {
            // If not specified, assume disabled by default
            config.disabledEventIds.push(id);
            config.rules.push({ eventId: id, name, enabled: false });
          }
        });
      } else {
        // No filtering means all events are enabled
        Object.entries(eventIdMap).forEach(([idStr, name]) => {
          const id = parseInt(idStr);
          config.enabledEventIds.push(id);
          config.rules.push({ eventId: id, name, enabled: true });
        });
      }

      return config;
    } catch (error) {
      console.error('Error parsing Sysmon config:', error);
      return null;
    }
  };

  // Parse Windows Audit Policy (auditpol /get /category:* output or CSV)
  const parseAuditPolicy = (text: string): WindowsAuditPolicy | null => {
    try {
      const policy: WindowsAuditPolicy = { categories: [] };
      const lines = text.split('\n').filter(l => l.trim());

      let currentCategory: { name: string; subcategories: { name: string; success: boolean; failure: boolean }[] } | null = null;

      for (const line of lines) {
        // Skip header lines
        if (line.includes('Machine Name:') || line.includes('Policy Target:') || line.includes('Category/Subcategory')) {
          continue;
        }

        // Check if it's a category line (no leading spaces or specific format)
        const categoryMatch = line.match(/^([A-Z][^,]+?)(?:\s*,|$)/i);
        const subcategoryMatch = line.match(/^\s{2,}([^,]+),\s*(Success|Failure|Success and Failure|No Auditing)/i);

        // CSV format: Category,Subcategory,Setting
        const csvMatch = line.match(/^([^,]+),([^,]+),(.+)$/);

        if (csvMatch) {
          const [, cat, subcat, setting] = csvMatch;
          let category = policy.categories.find(c => c.name === cat.trim());
          if (!category) {
            category = { name: cat.trim(), subcategories: [] };
            policy.categories.push(category);
          }
          category.subcategories.push({
            name: subcat.trim(),
            success: setting.toLowerCase().includes('success'),
            failure: setting.toLowerCase().includes('failure'),
          });
        } else if (subcategoryMatch && currentCategory) {
          const [, name, setting] = subcategoryMatch;
          currentCategory.subcategories.push({
            name: name.trim(),
            success: setting.toLowerCase().includes('success'),
            failure: setting.toLowerCase().includes('failure'),
          });
        } else if (categoryMatch && !line.startsWith(' ')) {
          if (currentCategory && currentCategory.subcategories.length > 0) {
            policy.categories.push(currentCategory);
          }
          currentCategory = { name: categoryMatch[1].trim(), subcategories: [] };
        }
      }

      if (currentCategory && currentCategory.subcategories.length > 0) {
        policy.categories.push(currentCategory);
      }

      return policy.categories.length > 0 ? policy : null;
    } catch (error) {
      console.error('Error parsing audit policy:', error);
      return null;
    }
  };

  // Handle file upload
  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>, type: 'sysmon' | 'audit') => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploadError(null);
    const reader = new FileReader();

    reader.onload = (e) => {
      const content = e.target?.result as string;

      if (type === 'sysmon') {
        const config = parseSysmonConfig(content);
        if (config) {
          setSysmonConfig(config);
          // Re-run gap analysis if we have both configs
          if (auditPolicy) {
            runGapAnalysis(config, auditPolicy);
          }
        } else {
          setUploadError('Failed to parse Sysmon configuration. Please ensure it\'s a valid XML file.');
        }
      } else {
        const policy = parseAuditPolicy(content);
        if (policy) {
          setAuditPolicy(policy);
          // Re-run gap analysis if we have both configs
          if (sysmonConfig) {
            runGapAnalysis(sysmonConfig, policy);
          }
        } else {
          setUploadError('Failed to parse audit policy. Please use output from "auditpol /get /category:*" or a CSV export.');
        }
      }
    };

    reader.onerror = () => {
      setUploadError('Failed to read file');
    };

    reader.readAsText(file);
    event.target.value = ''; // Reset input
  };

  // Run gap analysis
  const runGapAnalysis = (sysmon: SysmonConfig, audit: WindowsAuditPolicy) => {
    const result: GapAnalysisResult = {
      passed: true,
      missingEventIds: [],
      missingAuditPolicies: [],
      recommendations: [],
    };

    // Check common required Sysmon Event IDs for threat hunting
    const requiredEventIds = [1, 3, 7, 8, 10, 11, 12, 13, 22, 23];
    requiredEventIds.forEach(id => {
      if (!sysmon.enabledEventIds.includes(id)) {
        result.missingEventIds.push(id);
        result.passed = false;
      }
    });

    // Check common required audit policies
    const requiredAuditPolicies = [
      { category: 'Logon/Logoff', subcategory: 'Logon', success: true, failure: true },
      { category: 'Object Access', subcategory: 'File System', success: true, failure: false },
      { category: 'Process Tracking', subcategory: 'Process Creation', success: true, failure: false },
      { category: 'Account Management', subcategory: 'User Account Management', success: true, failure: true },
    ];

    requiredAuditPolicies.forEach(req => {
      const category = audit.categories.find(c =>
        c.name.toLowerCase().includes(req.category.toLowerCase())
      );
      if (!category) {
        result.missingAuditPolicies.push(`${req.category} - ${req.subcategory}`);
        result.passed = false;
      } else {
        const subcategory = category.subcategories.find(s =>
          s.name.toLowerCase().includes(req.subcategory.toLowerCase())
        );
        if (!subcategory || (req.success && !subcategory.success) || (req.failure && !subcategory.failure)) {
          result.missingAuditPolicies.push(`${req.category} - ${req.subcategory}`);
          result.passed = false;
        }
      }
    });

    // Add recommendations
    if (result.missingEventIds.length > 0) {
      result.recommendations.push(
        `Enable Sysmon Event IDs: ${result.missingEventIds.join(', ')}. These are essential for threat detection.`
      );
    }
    if (result.missingAuditPolicies.length > 0) {
      result.recommendations.push(
        'Configure Windows Advanced Audit Policies for the missing categories using Group Policy or auditpol command.'
      );
    }
    if (result.passed) {
      result.recommendations.push('Your logging configuration meets the basic requirements for threat hunting!');
    }

    setGapAnalysis(result);
  };

  // Export mappings to JSON
  const exportMappings = () => {
    if (!selectedProfileId || mappings.length === 0) return;

    const profile = profiles.find(p => p.id === selectedProfileId);
    const exportData = {
      profile: profile?.name,
      index: profile?.default_index,
      sourcetype: profile?.default_sourcetype,
      mappings: mappings,
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sigma-mappings-${profile?.name || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Import mappings from JSON
  const handleImportMappings = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file || !selectedProfileId) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target?.result as string);
        if (data.mappings && Array.isArray(data.mappings)) {
          bulkUpdateMutation.mutate({
            profileId: selectedProfileId,
            mappings: data.mappings,
          });
        }
      } catch (error) {
        console.error('Failed to parse import file:', error);
      }
    };
    reader.readAsText(file);
    event.target.value = '';
  };

  const selectedProfile = profiles.find(p => p.id === selectedProfileId);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Sigma Mappings & Configuration</h1>
          <p className="text-gray-400 mt-1">
            Manage field mappings and verify your logging configuration
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Profiles List */}
        <div className="lg:col-span-1 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Profiles</h2>
            <button
              onClick={() => setIsCreatingProfile(true)}
              className="p-1.5 text-gray-400 hover:text-cyan-400 hover:bg-gray-800 rounded transition-colors"
              title="Create new profile"
            >
              <Plus size={18} />
            </button>
          </div>

          {loadingProfiles ? (
            <div className="flex items-center justify-center p-8">
              <Loader2 className="animate-spin text-gray-400" size={24} />
            </div>
          ) : (
            <div className="space-y-2">
              {/* Create Profile Form */}
              {isCreatingProfile && (
                <div className="p-3 bg-gray-800 rounded-lg border border-cyan-500/50 space-y-3">
                  <input
                    type="text"
                    placeholder="Profile name"
                    value={newProfileName}
                    onChange={(e) => setNewProfileName(e.target.value)}
                    className="w-full bg-gray-900 text-gray-100 text-sm rounded px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                  />
                  <input
                    type="text"
                    placeholder="Default index (e.g., windows)"
                    value={newProfileIndex}
                    onChange={(e) => setNewProfileIndex(e.target.value)}
                    className="w-full bg-gray-900 text-gray-100 text-sm rounded px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                  />
                  <input
                    type="text"
                    placeholder="Default sourcetype"
                    value={newProfileSourcetype}
                    onChange={(e) => setNewProfileSourcetype(e.target.value)}
                    className="w-full bg-gray-900 text-gray-100 text-sm rounded px-3 py-2 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={() => createProfileMutation.mutate({
                        name: newProfileName,
                        default_index: newProfileIndex,
                        default_sourcetype: newProfileSourcetype,
                      })}
                      disabled={!newProfileName.trim()}
                      className="flex-1 px-3 py-1.5 bg-cyan-500 text-white text-sm rounded hover:bg-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      Create
                    </button>
                    <button
                      onClick={() => {
                        setIsCreatingProfile(false);
                        setNewProfileName('');
                        setNewProfileIndex('');
                        setNewProfileSourcetype('');
                      }}
                      className="px-3 py-1.5 bg-gray-700 text-gray-300 text-sm rounded hover:bg-gray-600"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Profile Cards */}
              {profiles.map((profile) => (
                <div
                  key={profile.id}
                  onClick={() => setSelectedProfileId(profile.id)}
                  className={cn(
                    "p-3 rounded-lg border cursor-pointer transition-all",
                    selectedProfileId === profile.id
                      ? "bg-cyan-500/10 border-cyan-500/50"
                      : "bg-gray-800/50 border-gray-700 hover:border-gray-600"
                  )}
                >
                  {editingProfile?.id === profile.id ? (
                    <div className="space-y-2" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="text"
                        value={editingProfile.name}
                        onChange={(e) => setEditingProfile({ ...editingProfile, name: e.target.value })}
                        className="w-full bg-gray-900 text-gray-100 text-sm rounded px-2 py-1 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                      />
                      <input
                        type="text"
                        value={editingProfile.default_index || ''}
                        onChange={(e) => setEditingProfile({ ...editingProfile, default_index: e.target.value })}
                        placeholder="Index"
                        className="w-full bg-gray-900 text-gray-100 text-sm rounded px-2 py-1 border border-gray-700 focus:border-cyan-500 focus:outline-none"
                      />
                      <div className="flex gap-1">
                        <button
                          onClick={() => updateProfileMutation.mutate({
                            id: profile.id,
                            data: {
                              name: editingProfile.name,
                              default_index: editingProfile.default_index,
                              default_sourcetype: editingProfile.default_sourcetype,
                            },
                          })}
                          className="p-1 text-green-400 hover:bg-gray-700 rounded"
                        >
                          <Save size={14} />
                        </button>
                        <button
                          onClick={() => setEditingProfile(null)}
                          className="p-1 text-gray-400 hover:bg-gray-700 rounded"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-white">{profile.name}</span>
                        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => setEditingProfile(profile)}
                            className="p-1 text-gray-400 hover:text-cyan-400 hover:bg-gray-700 rounded"
                          >
                            <Edit2 size={14} />
                          </button>
                          <button
                            onClick={() => {
                              if (confirm('Delete this profile?')) {
                                deleteProfileMutation.mutate(profile.id);
                              }
                            }}
                            className="p-1 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </div>
                      <div className="mt-2 space-y-1 text-xs text-gray-400">
                        {profile.default_index && (
                          <div className="flex items-center gap-1">
                            <Database size={12} />
                            <span>index={profile.default_index}</span>
                          </div>
                        )}
                        {profile.default_sourcetype && (
                          <div className="flex items-center gap-1">
                            <FileCode size={12} />
                            <span>sourcetype={profile.default_sourcetype}</span>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              ))}

              {profiles.length === 0 && !isCreatingProfile && (
                <p className="text-gray-500 text-sm text-center py-4">
                  No profiles yet. Create one to start mapping fields.
                </p>
              )}
            </div>
          )}
        </div>

        {/* Main Content */}
        <div className="lg:col-span-3 space-y-4">
          {/* Tabs */}
          <div className="flex gap-1 p-1 bg-gray-800/50 rounded-lg w-fit">
            <button
              onClick={() => setActiveTab('mappings')}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
                activeTab === 'mappings'
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "text-gray-400 hover:text-gray-200"
              )}
            >
              <Settings size={16} />
              Field Mappings
            </button>
            <button
              onClick={() => setActiveTab('sysmon')}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
                activeTab === 'sysmon'
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "text-gray-400 hover:text-gray-200"
              )}
            >
              <Shield size={16} />
              Sysmon Config
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={cn(
                "flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors",
                activeTab === 'audit'
                  ? "bg-cyan-500/20 text-cyan-400"
                  : "text-gray-400 hover:text-gray-200"
              )}
            >
              <FileCode size={16} />
              Audit Policy
            </button>
          </div>

          {/* Tab Content */}
          {activeTab === 'mappings' && (
            <div className="bg-gray-900 rounded-lg border border-gray-700">
              {!selectedProfileId ? (
                <div className="flex flex-col items-center justify-center p-12 text-gray-500">
                  <Settings size={48} className="mb-4 opacity-50" />
                  <p>Select a profile to view and edit field mappings</p>
                </div>
              ) : loadingMappings ? (
                <div className="flex items-center justify-center p-12">
                  <Loader2 className="animate-spin text-gray-400" size={24} />
                </div>
              ) : (
                <>
                  {/* Mappings Header */}
                  <div className="flex items-center justify-between p-4 border-b border-gray-700">
                    <h3 className="font-semibold text-white">
                      {selectedProfile?.name} - Field Mappings ({mappings.length})
                    </h3>
                    <div className="flex gap-2">
                      <label className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 hover:text-white cursor-pointer transition-colors">
                        <Upload size={14} />
                        Import
                        <input
                          type="file"
                          accept=".json"
                          onChange={handleImportMappings}
                          className="hidden"
                        />
                      </label>
                      <button
                        onClick={exportMappings}
                        disabled={mappings.length === 0}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                      >
                        <Download size={14} />
                        Export
                      </button>
                      <button
                        onClick={() => setIsAddingMapping(true)}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-cyan-500/20 text-cyan-400 rounded hover:bg-cyan-500/30 transition-colors"
                      >
                        <Plus size={14} />
                        Add Mapping
                      </button>
                    </div>
                  </div>

                  {/* Mappings Table */}
                  <div className="overflow-x-auto">
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-gray-700 text-left">
                          <th className="px-4 py-3 text-sm font-medium text-gray-400">Sigma Field</th>
                          <th className="px-4 py-3 text-sm font-medium text-gray-400">
                            <ChevronRight size={14} className="inline" />
                          </th>
                          <th className="px-4 py-3 text-sm font-medium text-gray-400">SPL Field</th>
                          <th className="px-4 py-3 text-sm font-medium text-gray-400">Transform</th>
                          <th className="px-4 py-3 text-sm font-medium text-gray-400 w-24">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {/* Add new mapping row */}
                        {isAddingMapping && (
                          <tr className="border-b border-gray-700 bg-cyan-500/5">
                            <td className="px-4 py-2">
                              <input
                                type="text"
                                value={newMapping.sigma_field}
                                onChange={(e) => setNewMapping({ ...newMapping, sigma_field: e.target.value })}
                                placeholder="e.g., CommandLine"
                                className="w-full bg-gray-800 text-gray-100 text-sm rounded px-2 py-1 border border-gray-600 focus:border-cyan-500 focus:outline-none"
                              />
                            </td>
                            <td className="px-4 py-2 text-gray-500">→</td>
                            <td className="px-4 py-2">
                              <input
                                type="text"
                                value={newMapping.target_field}
                                onChange={(e) => setNewMapping({ ...newMapping, target_field: e.target.value })}
                                placeholder="e.g., process_command_line"
                                className="w-full bg-gray-800 text-gray-100 text-sm rounded px-2 py-1 border border-gray-600 focus:border-cyan-500 focus:outline-none"
                              />
                            </td>
                            <td className="px-4 py-2">
                              <input
                                type="text"
                                value={newMapping.transform}
                                onChange={(e) => setNewMapping({ ...newMapping, transform: e.target.value })}
                                placeholder="optional"
                                className="w-full bg-gray-800 text-gray-100 text-sm rounded px-2 py-1 border border-gray-600 focus:border-cyan-500 focus:outline-none"
                              />
                            </td>
                            <td className="px-4 py-2">
                              <div className="flex gap-1">
                                <button
                                  onClick={() => addMappingMutation.mutate({
                                    profileId: selectedProfileId,
                                    mapping: newMapping,
                                  })}
                                  disabled={!newMapping.sigma_field || !newMapping.target_field}
                                  className="p-1 text-green-400 hover:bg-gray-700 rounded disabled:opacity-50"
                                >
                                  <Save size={14} />
                                </button>
                                <button
                                  onClick={() => {
                                    setIsAddingMapping(false);
                                    setNewMapping({ sigma_field: '', target_field: '', transform: '' });
                                  }}
                                  className="p-1 text-gray-400 hover:bg-gray-700 rounded"
                                >
                                  <X size={14} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        )}

                        {/* Existing mappings */}
                        {mappings.map((mapping) => (
                          <tr key={mapping.sigma_field} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                            <td className="px-4 py-2">
                              <code className="text-cyan-400 text-sm">{mapping.sigma_field}</code>
                            </td>
                            <td className="px-4 py-2 text-gray-500">→</td>
                            <td className="px-4 py-2">
                              {editingMapping?.sigma_field === mapping.sigma_field ? (
                                <input
                                  type="text"
                                  value={editingMapping.target_field}
                                  onChange={(e) => setEditingMapping({ ...editingMapping, target_field: e.target.value })}
                                  className="w-full bg-gray-800 text-gray-100 text-sm rounded px-2 py-1 border border-gray-600 focus:border-cyan-500 focus:outline-none"
                                />
                              ) : (
                                <code className="text-green-400 text-sm">{mapping.target_field}</code>
                              )}
                            </td>
                            <td className="px-4 py-2 text-gray-400 text-sm">
                              {mapping.transform || '-'}
                            </td>
                            <td className="px-4 py-2">
                              {editingMapping?.sigma_field === mapping.sigma_field ? (
                                <div className="flex gap-1">
                                  <button
                                    onClick={() => bulkUpdateMutation.mutate({
                                      profileId: selectedProfileId,
                                      mappings: mappings.map(m =>
                                        m.sigma_field === mapping.sigma_field ? editingMapping : m
                                      ),
                                    })}
                                    className="p-1 text-green-400 hover:bg-gray-700 rounded"
                                  >
                                    <Save size={14} />
                                  </button>
                                  <button
                                    onClick={() => setEditingMapping(null)}
                                    className="p-1 text-gray-400 hover:bg-gray-700 rounded"
                                  >
                                    <X size={14} />
                                  </button>
                                </div>
                              ) : (
                                <div className="flex gap-1">
                                  <button
                                    onClick={() => setEditingMapping(mapping)}
                                    className="p-1 text-gray-400 hover:text-cyan-400 hover:bg-gray-700 rounded"
                                  >
                                    <Edit2 size={14} />
                                  </button>
                                  <button
                                    onClick={() => {
                                      if (confirm('Delete this mapping?')) {
                                        deleteMappingMutation.mutate({
                                          profileId: selectedProfileId,
                                          sigmaField: mapping.sigma_field,
                                        });
                                      }
                                    }}
                                    className="p-1 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                                  >
                                    <Trash2 size={14} />
                                  </button>
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}

                        {mappings.length === 0 && !isAddingMapping && (
                          <tr>
                            <td colSpan={5} className="px-4 py-8 text-center text-gray-500">
                              No field mappings yet. Add some to customize Sigma to SPL conversion.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </>
              )}
            </div>
          )}

          {activeTab === 'sysmon' && (
            <div className="bg-gray-900 rounded-lg border border-gray-700 p-6 space-y-6">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold text-white">Sysmon Configuration</h3>
                  <p className="text-sm text-gray-400 mt-1">
                    Upload your Sysmon configuration XML to verify Event ID coverage
                  </p>
                </div>
                <label className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg cursor-pointer hover:bg-cyan-500/30 transition-colors">
                  <Upload size={16} />
                  Upload Config
                  <input
                    type="file"
                    accept=".xml"
                    onChange={(e) => handleFileUpload(e, 'sysmon')}
                    className="hidden"
                  />
                </label>
              </div>

              {uploadError && activeTab === 'sysmon' && (
                <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <AlertTriangle className="text-red-400 flex-shrink-0 mt-0.5" size={16} />
                  <p className="text-red-400 text-sm">{uploadError}</p>
                </div>
              )}

              {sysmonConfig ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-4 p-3 bg-gray-800/50 rounded-lg">
                    <div>
                      <span className="text-xs text-gray-400">Schema Version</span>
                      <p className="text-white font-medium">{sysmonConfig.schemaVersion}</p>
                    </div>
                    <div className="h-8 w-px bg-gray-700" />
                    <div>
                      <span className="text-xs text-gray-400">Enabled Events</span>
                      <p className="text-green-400 font-medium">{sysmonConfig.enabledEventIds.length}</p>
                    </div>
                    <div>
                      <span className="text-xs text-gray-400">Disabled Events</span>
                      <p className="text-gray-400 font-medium">{sysmonConfig.disabledEventIds.length}</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                    {sysmonConfig.rules.map((rule) => (
                      <div
                        key={rule.eventId}
                        className={cn(
                          "p-2 rounded border text-sm",
                          rule.enabled
                            ? "bg-green-500/10 border-green-500/30 text-green-400"
                            : "bg-gray-800/50 border-gray-700 text-gray-500"
                        )}
                      >
                        <div className="flex items-center gap-2">
                          {rule.enabled ? (
                            <CheckCircle size={14} />
                          ) : (
                            <X size={14} />
                          )}
                          <span className="font-mono">ID {rule.eventId}</span>
                        </div>
                        <p className="text-xs mt-1 truncate" title={rule.name}>
                          {rule.name}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center p-12 text-gray-500 border-2 border-dashed border-gray-700 rounded-lg">
                  <Shield size={48} className="mb-4 opacity-50" />
                  <p>No Sysmon configuration loaded</p>
                  <p className="text-xs mt-1">Upload your Sysmon XML config file to analyze Event ID coverage</p>
                </div>
              )}
            </div>
          )}

          {activeTab === 'audit' && (
            <div className="bg-gray-900 rounded-lg border border-gray-700 p-6 space-y-6">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="font-semibold text-white">Windows Audit Policy</h3>
                  <p className="text-sm text-gray-400 mt-1">
                    Upload output from <code className="bg-gray-800 px-1 rounded">auditpol /get /category:*</code>
                  </p>
                </div>
                <label className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 text-cyan-400 rounded-lg cursor-pointer hover:bg-cyan-500/30 transition-colors">
                  <Upload size={16} />
                  Upload Policy
                  <input
                    type="file"
                    accept=".txt,.csv"
                    onChange={(e) => handleFileUpload(e, 'audit')}
                    className="hidden"
                  />
                </label>
              </div>

              {uploadError && activeTab === 'audit' && (
                <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
                  <AlertTriangle className="text-red-400 flex-shrink-0 mt-0.5" size={16} />
                  <p className="text-red-400 text-sm">{uploadError}</p>
                </div>
              )}

              {auditPolicy ? (
                <div className="space-y-4">
                  {auditPolicy.categories.map((category) => (
                    <div key={category.name} className="border border-gray-700 rounded-lg overflow-hidden">
                      <div className="px-4 py-2 bg-gray-800/50 border-b border-gray-700">
                        <h4 className="font-medium text-white">{category.name}</h4>
                      </div>
                      <div className="p-2 grid grid-cols-1 md:grid-cols-2 gap-2">
                        {category.subcategories.map((sub) => (
                          <div
                            key={sub.name}
                            className="flex items-center justify-between p-2 bg-gray-800/30 rounded"
                          >
                            <span className="text-sm text-gray-300">{sub.name}</span>
                            <div className="flex gap-2 text-xs">
                              <span className={cn(
                                "px-1.5 py-0.5 rounded",
                                sub.success ? "bg-green-500/20 text-green-400" : "bg-gray-700 text-gray-500"
                              )}>
                                S
                              </span>
                              <span className={cn(
                                "px-1.5 py-0.5 rounded",
                                sub.failure ? "bg-yellow-500/20 text-yellow-400" : "bg-gray-700 text-gray-500"
                              )}>
                                F
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center p-12 text-gray-500 border-2 border-dashed border-gray-700 rounded-lg">
                  <FileCode size={48} className="mb-4 opacity-50" />
                  <p>No audit policy loaded</p>
                  <p className="text-xs mt-1">Run <code className="bg-gray-800 px-1 rounded">auditpol /get /category:*</code> and upload the output</p>
                </div>
              )}
            </div>
          )}

          {/* Gap Analysis Results */}
          {gapAnalysis && (sysmonConfig || auditPolicy) && (
            <div className={cn(
              "p-4 rounded-lg border",
              gapAnalysis.passed
                ? "bg-green-500/10 border-green-500/30"
                : "bg-yellow-500/10 border-yellow-500/30"
            )}>
              <div className="flex items-start gap-3">
                {gapAnalysis.passed ? (
                  <CheckCircle className="text-green-400 flex-shrink-0" size={20} />
                ) : (
                  <AlertTriangle className="text-yellow-400 flex-shrink-0" size={20} />
                )}
                <div className="flex-1">
                  <h4 className={cn(
                    "font-semibold",
                    gapAnalysis.passed ? "text-green-400" : "text-yellow-400"
                  )}>
                    Gap Analysis Results
                  </h4>

                  {gapAnalysis.missingEventIds.length > 0 && (
                    <div className="mt-2">
                      <p className="text-sm text-gray-300">Missing Sysmon Event IDs:</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {gapAnalysis.missingEventIds.map(id => (
                          <span key={id} className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">
                            ID {id}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {gapAnalysis.missingAuditPolicies.length > 0 && (
                    <div className="mt-2">
                      <p className="text-sm text-gray-300">Missing Audit Policies:</p>
                      <ul className="mt-1 space-y-1">
                        {gapAnalysis.missingAuditPolicies.map((policy, idx) => (
                          <li key={idx} className="text-sm text-red-400 flex items-center gap-1">
                            <X size={12} />
                            {policy}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {gapAnalysis.recommendations.length > 0 && (
                    <div className="mt-3 p-3 bg-gray-800/50 rounded">
                      <p className="text-sm font-medium text-gray-300 flex items-center gap-1">
                        <Info size={14} />
                        Recommendations
                      </p>
                      <ul className="mt-2 space-y-1">
                        {gapAnalysis.recommendations.map((rec, idx) => (
                          <li key={idx} className="text-sm text-gray-400">• {rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
