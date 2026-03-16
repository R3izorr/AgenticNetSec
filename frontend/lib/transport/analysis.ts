export interface JobStatusResponseTransport {
  analysis_job_id: string
  status: string
  current_phase: string
  progress: number
  guardrail_state: string
  error?: string | null
}

export interface HeaderBlockTransport {
  case_id: string
  timestamp: string
  analyst_mode: string
  data_sources: string[]
}

export interface EvidenceBlockTransport {
  key_packets_flows: string[]
  ioc_list: string[]
  suspicious_sessions: string[]
  correlated_events_timeline: string[]
}

export interface FindingsBlockTransport {
  primary_finding: string
  supporting_evidence: string[]
  confidence_score: number
  alternative_hypotheses: string[]
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
  llm_tokens_in: number
  llm_tokens_out: number
  cost_compute: number
  cost_llm: number
  cost_storage: number
  estimated_cost_total: number
}

export interface ReportMarkdownTransport {
  markdown: string
}
