export interface Playbook {
  id: string;
  name: string;
  description: string;
  mitre: {
    technique: string;
    tactic: string;
    subtechniques?: string[];
  };
  severity: 'critical' | 'high' | 'medium' | 'low';
  author: string;
  created: string;
  updated: string;
  data_sources: string[];
  hunt_hypothesis: string;
  queries: {
    splunk?: string;
    elastic?: string;
    sigma?: string;
  };
  queries_content?: {
    splunk?: string;
    elastic?: string;
    sigma?: string;
  };
  investigation_steps: string[];
  false_positives: string[];
  iocs?: IOC[];
  references: string[];
  tags: string[];
  tactic?: string;
  technique?: string;
  response?: {
    containment?: string[];
    eradication?: string[];
    recovery?: string[];
    quick_wins?: string[];
  };
}

export interface IOC {
  type: string;
  value: string;
  context: string;
}

export interface SearchFilters {
  query?: string;
  technique?: string;
  tactic?: string;
  tag?: string;
  severity?: string;
}

export interface APIStats {
  total_playbooks: number;
  by_tactic: Record<string, number>;
  by_severity: Record<string, number>;
  ai_available: boolean;
  supported_siems: string[];
}

export interface ExportResponse {
  playbook_id: string;
  siem: string;
  query: string;
}

export interface AIResponse {
  question?: string;
  answer?: string;
  explanation?: string;
  suggestions?: string;
  variant?: string;
}
