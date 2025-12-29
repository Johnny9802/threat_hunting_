import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '/api',
  timeout: 60000, // Longer timeout for LLM operations
  headers: {
    'Content-Type': 'application/json',
  },
});

// Types
export interface SigmaProfile {
  id: number;
  name: string;
  description?: string;
  default_index?: string;
  default_sourcetype?: string;
  cim_enabled?: boolean;
  is_default?: boolean;
  macros?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
}

export interface FieldMapping {
  id?: number;
  profile_id?: number;
  sigma_field: string;
  target_field: string;
  transform?: string;
  status?: 'ok' | 'missing' | 'suggested';
  category?: string;
  notes?: string;
  created_at?: string;
  updated_at?: string;
}

export interface SigmaRule {
  path: string;
  filename: string;
  title: string;
  status?: string;
  level?: string;
  product?: string;
  service?: string;
  category?: string;
  tags: string[];
  description?: string;
}

export interface RequiredLogSource {
  name: string;
  description: string;
  windows_channel?: string;
  splunk_sourcetype?: string;
  event_ids: Array<{ id: number; name: string; source: string }>;
  setup_instructions: string[];
}

export interface PrerequisiteInfo {
  log_source: Record<string, string | null>;
  required_logs: RequiredLogSource[];
  event_ids: Array<{ id: number; name: string; source: string }>;
  channels: string[];
  configuration: string[];
}

export interface GapItem {
  field: string;
  location: string;
  impact: string;
  suggestions: string[];
}

export interface HealthCheck {
  name: string;
  description: string;
  query: string;
}

export interface MappingResult {
  sigma_field: string;
  target_field: string | null;
  status: 'ok' | 'missing' | 'suggested';
}

export interface ConversionResponse {
  id?: number;
  name: string;
  spl: string;
  sigma_yaml?: string;
  prerequisites: PrerequisiteInfo;
  mappings: MappingResult[];
  gaps: GapItem[];
  health_checks: HealthCheck[];
  correlation_notes?: string;
  llm_used: boolean;
}

export interface ConversionHistory {
  id: number;
  name: string;
  conversion_type: 'sigma_to_spl' | 'spl_to_sigma' | 'text_to_sigma';
  profile_id?: number;
  input_content: string;
  output_sigma?: string;
  output_spl?: string;
  prerequisites?: PrerequisiteInfo;
  gap_analysis?: GapItem[];
  health_checks?: HealthCheck[];
  correlation_notes?: string;
  llm_used: boolean;
  created_at: string;
}

// Repository
export const getSigmaRepoStatus = async () => {
  const response = await api.get('/sigma/repo');
  return response.data;
};

export const listSigmaRules = async (params: {
  search?: string;
  product?: string;
  service?: string;
  category?: string;
  limit?: number;
  offset?: number;
}) => {
  const response = await api.get('/sigma/rules', { params });
  return response.data;
};

export const getSigmaRule = async (path: string) => {
  const response = await api.get(`/sigma/rules/${path}`);
  return response.data;
};

export const getSigmaFilters = async () => {
  const response = await api.get('/sigma/filters');
  return response.data;
};

// Conversion
export const convertSigmaToSpl = async (params: {
  sigma_yaml: string;
  profile_id?: number;
  cim_override?: boolean;
  index_override?: string;
  sourcetype_override?: string;
  time_range?: string;
}): Promise<ConversionResponse> => {
  const response = await api.post('/sigma/convert/sigma-to-spl', params);
  return response.data;
};

export const convertSplToSigma = async (params: {
  spl_query: string;
  title?: string;
  level?: string;
  status?: string;
  author?: string;
  description?: string;
}): Promise<ConversionResponse> => {
  const response = await api.post('/sigma/convert/spl-to-sigma', params);
  return response.data;
};

export const generateFromDescription = async (params: {
  description: string;
  log_source?: string;
  level?: string;
  include_false_positives?: boolean;
  include_attack_techniques?: boolean;
}): Promise<ConversionResponse> => {
  const response = await api.post('/sigma/convert/describe', params);
  return response.data;
};

// Profiles
export const listProfiles = async (): Promise<SigmaProfile[]> => {
  const response = await api.get('/sigma/profiles');
  return response.data;
};

export const getProfile = async (id: number): Promise<SigmaProfile> => {
  const response = await api.get(`/sigma/profiles/${id}`);
  return response.data;
};

export const createProfile = async (profile: Partial<SigmaProfile>): Promise<SigmaProfile> => {
  const response = await api.post('/sigma/profiles', profile);
  return response.data;
};

export const updateProfile = async (id: number, updates: Partial<SigmaProfile>): Promise<SigmaProfile> => {
  const response = await api.patch(`/sigma/profiles/${id}`, updates);
  return response.data;
};

export const deleteProfile = async (id: number): Promise<{ message: string }> => {
  const response = await api.delete(`/sigma/profiles/${id}`);
  return response.data;
};

// Field Mappings
export const getProfileMappings = async (profileId: number): Promise<FieldMapping[]> => {
  const response = await api.get(`/sigma/profiles/${profileId}/mappings`);
  return response.data;
};

export const createMapping = async (profileId: number, mapping: Partial<FieldMapping>): Promise<FieldMapping> => {
  const response = await api.post(`/sigma/profiles/${profileId}/mappings`, mapping);
  return response.data;
};

export const updateMapping = async (
  profileId: number,
  mappingId: number,
  updates: Partial<FieldMapping>
): Promise<FieldMapping> => {
  const response = await api.patch(`/sigma/profiles/${profileId}/mappings/${mappingId}`, updates);
  return response.data;
};

export const deleteMapping = async (profileId: number, sigmaField: string): Promise<{ message: string }> => {
  const response = await api.delete(`/sigma/profiles/${profileId}/mappings/${encodeURIComponent(sigmaField)}`);
  return response.data;
};

export const addMapping = async (
  profileId: number,
  mapping: { sigma_field: string; target_field: string; transform?: string }
): Promise<FieldMapping> => {
  const response = await api.post(`/sigma/profiles/${profileId}/mappings`, mapping);
  return response.data;
};

export const bulkUpdateMappings = async (
  profileId: number,
  mappings: FieldMapping[]
): Promise<{ updated: number }> => {
  const response = await api.post(`/sigma/profiles/${profileId}/mappings/bulk`, {
    profile_id: profileId,
    mappings,
  });
  return response.data;
};

export const bulkImportMappings = async (
  profileId: number,
  mappings: Array<Partial<FieldMapping>>
): Promise<{ imported: number }> => {
  const response = await api.post(`/sigma/profiles/${profileId}/mappings/bulk`, {
    profile_id: profileId,
    mappings,
  });
  return response.data;
};

export const suggestMappings = async (
  profileId: number,
  fields: string[]
): Promise<Record<string, string>> => {
  const response = await api.post(`/sigma/profiles/${profileId}/mappings/suggest`, fields);
  return response.data;
};

// History
export const getConversionHistory = async (params?: {
  limit?: number;
  offset?: number;
  conversion_type?: string;
}): Promise<{ conversions: ConversionHistory[]; limit: number; offset: number }> => {
  const response = await api.get('/sigma/history', { params });
  return response.data;
};

export const getConversionDetail = async (id: number): Promise<ConversionHistory> => {
  const response = await api.get(`/sigma/history/${id}`);
  return response.data;
};

export const deleteConversion = async (id: number): Promise<{ message: string }> => {
  const response = await api.delete(`/sigma/history/${id}`);
  return response.data;
};

export const getConversionStats = async () => {
  const response = await api.get('/sigma/history/stats');
  return response.data;
};

// LLM Status
export const getSigmaLLMStatus = async () => {
  const response = await api.get('/sigma/llm/status');
  return response.data;
};

// ========== Sysmon Config ==========

export interface SysmonConfigData {
  id?: number;
  name: string;
  version: string;
  schema_version: string;
  enabled_event_ids: number[];
  disabled_event_ids: number[];
  rules: Array<{ eventId: number; name: string; enabled: boolean }>;
  raw_xml?: string;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export const listSysmonConfigs = async (): Promise<SysmonConfigData[]> => {
  const response = await api.get('/sigma/sysmon-configs');
  return response.data;
};

export const createSysmonConfig = async (config: Partial<SysmonConfigData>): Promise<SysmonConfigData> => {
  const response = await api.post('/sigma/sysmon-configs', config);
  return response.data;
};

export const getActiveSysmonConfig = async (): Promise<{ available: boolean; config: SysmonConfigData | null }> => {
  const response = await api.get('/sigma/sysmon-configs/active');
  return response.data;
};

export const getSysmonConfig = async (id: number): Promise<SysmonConfigData> => {
  const response = await api.get(`/sigma/sysmon-configs/${id}`);
  return response.data;
};

export const activateSysmonConfig = async (id: number): Promise<{ message: string }> => {
  const response = await api.put(`/sigma/sysmon-configs/${id}/activate`);
  return response.data;
};

export const deleteSysmonConfig = async (id: number): Promise<{ message: string }> => {
  const response = await api.delete(`/sigma/sysmon-configs/${id}`);
  return response.data;
};

// ========== Windows Audit Config ==========

export interface AuditConfigData {
  id?: number;
  name: string;
  categories: Array<{
    name: string;
    subcategories: Array<{ name: string; success: boolean; failure: boolean }>;
  }>;
  raw_content?: string;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export const listAuditConfigs = async (): Promise<AuditConfigData[]> => {
  const response = await api.get('/sigma/audit-configs');
  return response.data;
};

export const createAuditConfig = async (config: Partial<AuditConfigData>): Promise<AuditConfigData> => {
  const response = await api.post('/sigma/audit-configs', config);
  return response.data;
};

export const getActiveAuditConfig = async (): Promise<{ available: boolean; config: AuditConfigData | null }> => {
  const response = await api.get('/sigma/audit-configs/active');
  return response.data;
};

export const getAuditConfig = async (id: number): Promise<AuditConfigData> => {
  const response = await api.get(`/sigma/audit-configs/${id}`);
  return response.data;
};

export const activateAuditConfig = async (id: number): Promise<{ message: string }> => {
  const response = await api.put(`/sigma/audit-configs/${id}/activate`);
  return response.data;
};

export const deleteAuditConfig = async (id: number): Promise<{ message: string }> => {
  const response = await api.delete(`/sigma/audit-configs/${id}`);
  return response.data;
};

// ========== Log Coverage Check ==========

export interface CoverageCheckResult {
  sysmon_coverage: {
    available: boolean;
    enabled_ids: number[];
    missing_ids: number[];
    covered: boolean;
  };
  audit_coverage: {
    available: boolean;
    enabled_policies: string[];
    covered: boolean;
  };
  overall_covered: boolean;
  recommendations: string[];
}

export const checkLogCoverage = async (
  eventIds: number[],
  category?: string
): Promise<CoverageCheckResult> => {
  const response = await api.post('/sigma/check-coverage', {
    event_ids: eventIds,
    category,
  });
  return response.data;
};

export default api;
