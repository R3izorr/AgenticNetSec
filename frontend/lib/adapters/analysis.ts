import type {
  ForensicReportTransport,
  GuardrailAuditTransport,
  JobArtifactReadyTransport,
  JobMetadataTransport,
  JobStatusResponseTransport,
  RunMetricsTransport,
  Stage1ExecutionTransport,
  Stage1StepDecisionTransport,
  TotalJobStatusResponseTransport,
} from "@/lib/transport/analysis"
import type {
  ForensicReport,
  GuardrailAudit,
  JobArtifactReady,
  JobMetadata,
  JobStatus,
  RunMetrics,
  Stage1Execution,
  Stage1StepDecision,
  TotalJobStatus,
} from "@/lib/types/analysis"

function safeArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return []
  }
  return value.filter((item): item is string => typeof item === "string")
}

function safeNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback
}

function safeNullableNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null
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

function adaptJobMetadata(transport?: JobMetadataTransport | null): JobMetadata {
  return {
    filename: transport?.filename ?? null,
    path: transport?.path ?? null,
    sizeBytes: safeNullableNumber(transport?.size_bytes),
    packetCount: safeNullableNumber(transport?.packet_count),
    flowCount: safeNullableNumber(transport?.flow_count),
    captureStart: transport?.capture_start ?? null,
    captureEnd: transport?.capture_end ?? null,
  }
}

function adaptArtifactReady(
  transport?: JobArtifactReadyTransport | null
): JobArtifactReady {
  return {
    reportJson: Boolean(transport?.report_json),
    reportMarkdown: Boolean(transport?.report_markdown),
    metrics: Boolean(transport?.metrics),
    guardrailAudit: Boolean(transport?.guardrail_audit),
  }
}

function adaptStage1StepDecision(
  transport?: Stage1StepDecisionTransport | null
): Stage1StepDecision | null {
  if (!transport) {
    return null
  }
  return {
    executed: Boolean(transport.executed),
    reason: typeof transport.reason === "string" ? transport.reason : null,
    status: typeof transport.status === "string" ? transport.status : null,
  }
}

function adaptStage1Execution(
  transport?: Stage1ExecutionTransport | null
): Stage1Execution | null {
  if (!transport) {
    return null
  }
  return {
    requestedProfile:
      transport.requested_profile === "fast" ||
      transport.requested_profile === "standard" ||
      transport.requested_profile === "full"
        ? transport.requested_profile
        : null,
    deepDive: adaptStage1StepDecision(transport.deep_dive),
    payloadCarving: adaptStage1StepDecision(transport.payload_carving),
  }
}

export function adaptJobStatus(transport: JobStatusResponseTransport): JobStatus {
  return {
    analysisJobId: transport.analysis_job_id,
    groupId: transport.group_id ?? null,
    groupIndex:
      typeof transport.group_index === "number" && Number.isFinite(transport.group_index)
        ? transport.group_index
        : null,
    groupTotal:
      typeof transport.group_total === "number" && Number.isFinite(transport.group_total)
        ? transport.group_total
        : null,
    status: transport.status ?? "queued",
    currentPhase: transport.current_phase ?? "queued",
    progress: safeNumber(transport.progress, 0),
    guardrailState: transport.guardrail_state ?? "pending",
    error: transport.error ?? null,
    createdAt: transport.created_at,
    updatedAt: transport.updated_at,
    sourceType: transport.source_type ?? null,
    sourceName: transport.source_name ?? null,
    sourcePath: transport.source_path ?? null,
    metadata: adaptJobMetadata(transport.metadata),
    artifactReady: adaptArtifactReady(transport.artifact_ready),
    attackType: transport.attack_type ?? null,
    riskLevel: transport.risk_level ?? null,
    confidenceScore: safeNullableNumber(transport.confidence_score),
    runtimeSecondsTotal: safeNullableNumber(transport.runtime_seconds_total),
    analysisProfile:
      transport.analysis_profile === "fast" ||
      transport.analysis_profile === "standard" ||
      transport.analysis_profile === "full"
        ? transport.analysis_profile
        : null,
    stage1Execution: adaptStage1Execution(transport.stage1_execution),
  }
}

export function adaptTotalJobStatus(
  transport: TotalJobStatusResponseTransport
): TotalJobStatus {
  return {
    totalJobId: transport.total_job_id,
    status: transport.status ?? "queued",
    currentStage: transport.current_stage ?? "queued",
    progress: safeNumber(transport.progress, 0),
    createdAt: transport.created_at,
    updatedAt: transport.updated_at,
    error: transport.error ?? null,
    workerCount: safeNumber(transport.worker_count, 2),
    fileCount: safeNumber(transport.file_count, 0),
    completedChildren: safeNumber(transport.completed_children, 0),
    failedChildren: safeNumber(transport.failed_children, 0),
    deterministicComplete: Boolean(transport.deterministic_complete),
    enrichmentStatus: transport.enrichment_status ?? "not_started",
    enrichmentProgress: safeNumber(transport.enrichment_progress, 0),
    enrichmentError: transport.enrichment_error ?? null,
    analysisProfile:
      transport.analysis_profile === "fast" ||
      transport.analysis_profile === "standard" ||
      transport.analysis_profile === "full"
        ? transport.analysis_profile
        : null,
    children: Array.isArray(transport.children)
      ? transport.children.map((child) => ({
          analysisJobId: child.analysis_job_id,
          filename: child.filename,
          sourcePath: child.source_path ?? null,
          status: child.status ?? "queued",
          currentPhase: child.current_phase ?? "queued",
          progress: safeNumber(child.progress, 0),
          error: child.error ?? null,
          attackType: child.attack_type ?? null,
          riskLevel: child.risk_level ?? null,
          confidenceScore: safeNullableNumber(child.confidence_score),
          runtimeSecondsTotal: safeNullableNumber(child.runtime_seconds_total),
          analysisProfile:
            child.analysis_profile === "fast" ||
            child.analysis_profile === "standard" ||
            child.analysis_profile === "full"
              ? child.analysis_profile
              : null,
          stage1Execution: adaptStage1Execution(child.stage1_execution),
        }))
      : [],
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
      metadata: adaptJobMetadata(transport.header?.metadata),
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
