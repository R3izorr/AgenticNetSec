import type {
  ForensicReportTransport,
  GuardrailAuditTransport,
  JobStatusResponseTransport,
  RunMetricsTransport,
} from "@/lib/transport/analysis"
import type { ForensicReport, GuardrailAudit, JobStatus, RunMetrics } from "@/lib/types/analysis"

function safeArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === "string")
}

function safeNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback
}

function safeNumberArray(value: unknown): number[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is number => typeof item === "number" && Number.isFinite(item))
}

function safeRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function safePrimitiveRecord(
  value: unknown
): Record<string, string | number | boolean> {
  const source = safeRecord(value)
  const output: Record<string, string | number | boolean> = {}
  for (const [key, item] of Object.entries(source)) {
    if (
      typeof item === "string" ||
      (typeof item === "number" && Number.isFinite(item)) ||
      typeof item === "boolean"
    ) {
      output[key] = item
    }
  }
  return output
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
      evidenceRefs: Array.isArray(transport.evidence?.evidence_refs)
        ? transport.evidence.evidence_refs.map((ref) => ({
            refId: ref.ref_id ?? "N/A",
            detector: ref.detector ?? "unknown",
            claim: ref.claim ?? "unknown",
            sourceFile: ref.source_file ?? "N/A",
            summary: ref.summary ?? "N/A",
            frameNumbers: safeNumberArray(ref.frame_numbers),
            flow: ref.flow ?? "",
            wiresharkFilter: ref.wireshark_filter ?? "",
          }))
        : [],
    },
    findings: {
      primaryFinding: transport.findings?.primary_finding ?? "N/A",
      supportingEvidence: safeArray(transport.findings?.supporting_evidence),
      confidenceScore: safeNumber(transport.findings?.confidence_score, 0),
      alternativeHypotheses: safeArray(
        transport.findings?.alternative_hypotheses
      ),
      mitreTechniques: safeArray(transport.findings?.mitre_techniques),
      evidenceRefIds: safeArray(transport.findings?.evidence_ref_ids),
      directEvidence: safeArray(transport.findings?.direct_evidence),
      uncertainties: safeArray(transport.findings?.uncertainties),
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
    provider: transport.provider ?? "unknown",
    model: transport.model ?? "unknown",
    fallbackUsed: Boolean(transport.fallback_used),
    llmTokensIn: safeNumber(transport.llm_tokens_in, 0),
    llmTokensOut: safeNumber(transport.llm_tokens_out, 0),
    artifactBytes:
      transport.artifact_bytes &&
      typeof transport.artifact_bytes === "object"
        ? Object.fromEntries(
            Object.entries(transport.artifact_bytes).map(([key, value]) => [
              key,
              safeNumber(value, 0),
            ])
          )
        : {},
    costAssumptions: safePrimitiveRecord(transport.cost_assumptions),
    costCompute: safeNumber(transport.cost_compute, 0),
    costLlm: safeNumber(transport.cost_llm, 0),
    costStorage: safeNumber(transport.cost_storage, 0),
    estimatedCostTotal: safeNumber(transport.estimated_cost_total, 0),
  }
}

export function adaptGuardrailAudit(
  transport: Partial<GuardrailAuditTransport>
): GuardrailAudit {
  return {
    inputValidity: safeRecord(transport.input_validity),
    toolValidation: safeRecord(transport.tool_validation),
    claimChecks: Array.isArray(transport.claim_checks)
      ? transport.claim_checks.map((item) => safeRecord(item))
      : [],
    contradictions: safeArray(transport.contradictions),
    confidenceDecision: safeRecord(transport.confidence_decision),
    humanReviewRequired: transport.human_review_required ?? "Unknown",
    readOnlyMode: transport.read_only_mode ?? true,
  }
}
