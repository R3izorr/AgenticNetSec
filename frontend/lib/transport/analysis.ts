export interface JobMetadataTransport {
  filename?: string | null
  path?: string | null
  size_bytes?: number | null
  packet_count?: number | null
  flow_count?: number | null
  capture_start?: string | null
  capture_end?: string | null
}

export interface JobArtifactReadyTransport {
  report_json?: boolean
  report_markdown?: boolean
  metrics?: boolean
  guardrail_audit?: boolean
}

export interface JobStatusResponseTransport {
  analysis_job_id: string
  status: string
  current_phase: string
  progress: number
  guardrail_state: string
  error?: string | null
  created_at?: string
  updated_at?: string
  source_type?: string | null
  source_name?: string | null
  source_path?: string | null
  metadata?: JobMetadataTransport | null
  artifact_ready?: JobArtifactReadyTransport | null
  attack_type?: string | null
  risk_level?: string | null
  confidence_score?: number | null
  runtime_seconds_total?: number | null
}

export interface HeaderBlockTransport {
  case_id: string
  timestamp: string
  analyst_mode: string
  data_sources: string[]
  metadata?: JobMetadataTransport | null
}

export interface EvidenceBlockTransport {
  key_packets_flows: string[]
  ioc_list: string[]
  suspicious_sessions: string[]
  correlated_events_timeline: string[]
  evidence_refs?: EvidenceRefTransport[]
}

export interface EvidenceRefTransport {
  ref_id: string
  detector: string
  claim: string
  source_file: string
  summary: string
  frame_numbers: number[]
  flow: string
  wireshark_filter: string
}

export interface FindingsBlockTransport {
  primary_finding: string
  supporting_evidence: string[]
  confidence_score: number
  alternative_hypotheses: string[]
  mitre_techniques?: string[]
  evidence_ref_ids?: string[]
  direct_evidence?: string[]
  uncertainties?: string[]
  observation: string
  inference: string
  recommendation: string
}

export interface ImpactBlockTransport {
  affected_assets: string[]
  attack_type: string
  risk_level: string
}

export interface RecommendedActionsBlockTransport {
  immediate_containment: string[]
  validation_steps: string[]
  longer_term_hardening: string[]
}

export interface GuardrailVerificationBlockTransport {
  data_validity_check: string
  tool_output_validation: string
  human_review_required: string
}

export interface ForensicReportTransport {
  header: HeaderBlockTransport
  evidence: EvidenceBlockTransport
  findings: FindingsBlockTransport
  impact: ImpactBlockTransport
  recommended_actions: RecommendedActionsBlockTransport
  guardrail_verification: GuardrailVerificationBlockTransport
  analyst_summary_markdown: string
}

export interface RunMetricsTransport {
  status: string
  runtime_seconds_total: number
  phase_timings_seconds: Record<string, number>
  cpu_percent_peak: number | null
  ram_mb_peak: number | null
  provider?: string
  model?: string
  fallback_used?: boolean
  llm_tokens_in: number
  llm_tokens_out: number
  artifact_bytes?: Record<string, number>
  cost_assumptions?: Record<string, number | string | boolean>
  cost_compute: number
  cost_llm: number
  cost_storage: number
  estimated_cost_total: number
}

export interface ReportMarkdownTransport {
  markdown: string
}

export interface GuardrailAuditTransport {
  input_validity: Record<string, unknown>
  tool_validation: Record<string, unknown>
  claim_checks: Array<Record<string, unknown>>
  contradictions: string[]
  confidence_decision: Record<string, unknown>
  human_review_required: string
  read_only_mode: boolean
}
