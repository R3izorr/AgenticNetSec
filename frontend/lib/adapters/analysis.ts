import type {
  ForensicReportTransport,
  JobStatusResponseTransport,
  RunMetricsTransport,
} from "@/lib/transport/analysis"
import type { ForensicReport, JobStatus, RunMetrics } from "@/lib/types/analysis"

function safeArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === "string")
}

function safeNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback
}

export function adaptJobStatus(transport: JobStatusResponseTransport): JobStatus {
  return {
    analysisJobId: transport.analysis_job_id,
    status: transport.status ?? "queued",
    currentPhase: transport.current_phase ?? "queued",
    progress: safeNumber(transport.progress, 0),
    guardrailState: transport.guardrail_state ?? "pending",
    error: transport.error ?? null,
  }
}

export function adaptForensicReport(
  transport: Partial<ForensicReportTransport>
): ForensicReport {
  return {
    header: {
      caseId: transport.header?.case_id ?? "N/A",
      timestamp: transport.header?.timestamp ?? "N/A",
      analystMode: transport.header?.analyst_mode ?? "Autonomous Agent",
      dataSources: safeArray(transport.header?.data_sources),
    },
    evidence: {
      keyPacketsFlows: safeArray(transport.evidence?.key_packets_flows),
      iocList: safeArray(transport.evidence?.ioc_list),
      suspiciousSessions: safeArray(transport.evidence?.suspicious_sessions),
      correlatedEventsTimeline: safeArray(
        transport.evidence?.correlated_events_timeline
      ),
    },
    findings: {
      primaryFinding: transport.findings?.primary_finding ?? "N/A",
      supportingEvidence: safeArray(transport.findings?.supporting_evidence),
      confidenceScore: safeNumber(transport.findings?.confidence_score, 0),
      alternativeHypotheses: safeArray(
        transport.findings?.alternative_hypotheses
      ),
      observation: transport.findings?.observation ?? "N/A",
      inference: transport.findings?.inference ?? "N/A",
      recommendation: transport.findings?.recommendation ?? "N/A",
    },
    impact: {
      affectedAssets: safeArray(transport.impact?.affected_assets),
      attackType: transport.impact?.attack_type ?? "unknown",
      riskLevel: transport.impact?.risk_level ?? "low",
    },
    recommendedActions: {
      immediateContainment: safeArray(
        transport.recommended_actions?.immediate_containment
      ),
      validationSteps: safeArray(transport.recommended_actions?.validation_steps),
      longerTermHardening: safeArray(
        transport.recommended_actions?.longer_term_hardening
      ),
    },
    guardrailVerification: {
      dataValidityCheck:
        transport.guardrail_verification?.data_validity_check ?? "unknown",
      toolOutputValidation:
        transport.guardrail_verification?.tool_output_validation ?? "unknown",
      humanReviewRequired:
        transport.guardrail_verification?.human_review_required ?? "Unknown",
    },
    analystSummaryMarkdown: transport.analyst_summary_markdown ?? "",
  }
}

export function adaptRunMetrics(transport: Partial<RunMetricsTransport>): RunMetrics {
  return {
    status: transport.status ?? "unknown",
    runtimeSecondsTotal: safeNumber(transport.runtime_seconds_total, 0),
    phaseTimingsSeconds:
      transport.phase_timings_seconds &&
      typeof transport.phase_timings_seconds === "object"
        ? transport.phase_timings_seconds
        : {},
    cpuPercentPeak:
      typeof transport.cpu_percent_peak === "number"
        ? transport.cpu_percent_peak
        : null,
    ramMbPeak:
      typeof transport.ram_mb_peak === "number" ? transport.ram_mb_peak : null,
    llmTokensIn: safeNumber(transport.llm_tokens_in, 0),
    llmTokensOut: safeNumber(transport.llm_tokens_out, 0),
    costCompute: safeNumber(transport.cost_compute, 0),
    costLlm: safeNumber(transport.cost_llm, 0),
    costStorage: safeNumber(transport.cost_storage, 0),
    estimatedCostTotal: safeNumber(transport.estimated_cost_total, 0),
  }
}
