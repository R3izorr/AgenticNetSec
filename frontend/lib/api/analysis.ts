import { apiRequest } from "@/lib/api/client"
import type {
  ForensicReportTransport,
  GuardrailAuditTransport,
  JobStatusResponseTransport,
  ReportMarkdownTransport,
  RunMetricsTransport,
} from "@/lib/transport/analysis"
import type { CreateAnalysisInput, JobStatus } from "@/lib/types/analysis"
import { adaptJobStatus } from "@/lib/adapters/analysis"

export interface JobHistoryResponseRaw {
  total: number
  jobs: JobStatusResponseTransport[]
}

export interface JobHistoryResponse {
  total: number
  jobs: JobStatus[]
}

export interface BatchCreateAnalysisResponse {
  group_id: string
  jobs: JobStatusResponseTransport[]
}

export async function createAnalysisJob(
  input: CreateAnalysisInput
): Promise<JobStatusResponseTransport> {
  const hasFile = Boolean(input.file)
  const hasPath = Boolean(input.pcapPath?.trim())
  if (hasFile === hasPath) {
    throw new Error("Provide exactly one input source: file or pcapPath.")
  }

  const formData = new FormData()
  if (input.file) {
    formData.append("file", input.file)
  }
  if (input.pcapPath?.trim()) {
    formData.append("pcap_path", input.pcapPath.trim())
  }
  if (input.provider?.trim()) {
    formData.append("provider", input.provider.trim())
  }
  if (input.model?.trim()) {
    formData.append("model", input.model.trim())
  }
  if (typeof input.useAi === "boolean") {
    formData.append("use_ai", String(input.useAi))
  }
  if (typeof input.requireAi === "boolean") {
    formData.append("require_ai", String(input.requireAi))
  }

  return apiRequest<JobStatusResponseTransport>("/api/v1/analysis", {
    method: "POST",
    body: formData,
  })
}

export interface BatchCreateAnalysisInput {
  files: File[]
  provider?: string
  model?: string
  useAi?: boolean
  requireAi?: boolean
}

export async function createBatchAnalysisJob(
  input: BatchCreateAnalysisInput,
): Promise<BatchCreateAnalysisResponse> {
  if (!input.files.length) {
    throw new Error("At least one file is required for batch analysis.")
  }

  const formData = new FormData()
  for (const file of input.files) {
    formData.append("files", file)
  }
  if (input.provider?.trim()) {
    formData.append("provider", input.provider.trim())
  }
  if (input.model?.trim()) {
    formData.append("model", input.model.trim())
  }
  if (typeof input.useAi === "boolean") {
    formData.append("use_ai", String(input.useAi))
  }
  if (typeof input.requireAi === "boolean") {
    formData.append("require_ai", String(input.requireAi))
  }

  return apiRequest<BatchCreateAnalysisResponse>("/api/v1/analysis/batch", {
    method: "POST",
    body: formData,
  })
}

export async function getJobHistory(
): Promise<JobHistoryResponse> {
  const raw = await apiRequest<JobHistoryResponseRaw>(
    `/api/v1/analysis`
  )
  return {
    total: raw.total,
    jobs: raw.jobs.map(adaptJobStatus),
  }
}

export async function getAnalysisJobStatus(
  jobId: string
): Promise<JobStatusResponseTransport> {
  return apiRequest<JobStatusResponseTransport>(`/api/v1/analysis/${jobId}`)
}

export async function getReportJson(jobId: string): Promise<ForensicReportTransport> {
  return apiRequest<ForensicReportTransport>(`/api/v1/analysis/${jobId}/report.json`)
}

export async function getReportMarkdown(jobId: string): Promise<ReportMarkdownTransport> {
  return apiRequest<ReportMarkdownTransport>(`/api/v1/analysis/${jobId}/report.md`)
}

export async function getMetrics(jobId: string): Promise<RunMetricsTransport> {
  return apiRequest<RunMetricsTransport>(`/api/v1/analysis/${jobId}/metrics`)
}

export async function getGuardrailAudit(
  jobId: string
): Promise<GuardrailAuditTransport> {
  return apiRequest<GuardrailAuditTransport>(
    `/api/v1/analysis/${jobId}/guardrail-audit`
  )
}
