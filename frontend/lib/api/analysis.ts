import { apiRequest } from "@/lib/api/client"
import type {
  ForensicReportTransport,
  GuardrailAuditTransport,
  JobStatusResponseTransport,
  ReportMarkdownTransport,
  RunMetricsTransport,
  TotalJobSandboxTransport,
  TotalJobStatusResponseTransport,
  TotalJobSummaryJsonTransport,
} from "@/lib/transport/analysis"
import type {
  BatchCreateAnalysisInput,
  JobStatus,
  TotalJobStatus,
} from "@/lib/types/analysis"
import { adaptJobStatus, adaptTotalJobStatus } from "@/lib/adapters/analysis"

export interface JobHistoryResponseRaw {
  total: number
  jobs: JobStatusResponseTransport[]
}

export interface JobHistoryResponse {
  total: number
  jobs: JobStatus[]
}

export interface TotalJobListResponseRaw {
  total: number
  jobs: TotalJobStatusResponseTransport[]
}

export interface TotalJobListResponse {
  total: number
  jobs: TotalJobStatus[]
}

export async function createBatchAnalysisJob(
  input: BatchCreateAnalysisInput,
): Promise<TotalJobStatusResponseTransport> {
  if (!input.files.length) {
    throw new Error("At least one file is required for batch analysis.")
  }

  const formData = new FormData()
  for (const file of input.files) {
    formData.append("files", file)
  }
  formData.append("worker_count", String(input.workerCount))

  return apiRequest<TotalJobStatusResponseTransport>("/api/v1/analysis/batch", {
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

export async function getTotalJobs(): Promise<TotalJobListResponse> {
  const raw = await apiRequest<TotalJobListResponseRaw>("/api/v1/total-jobs")
  return {
    total: raw.total,
    jobs: raw.jobs.map(adaptTotalJobStatus),
  }
}

export async function getTotalJobStatus(
  totalJobId: string
): Promise<TotalJobStatusResponseTransport> {
  return apiRequest<TotalJobStatusResponseTransport>(`/api/v1/total-jobs/${totalJobId}`)
}

export async function triggerTotalJobEnrichment(
  totalJobId: string
): Promise<TotalJobStatusResponseTransport> {
  return apiRequest<TotalJobStatusResponseTransport>(`/api/v1/total-jobs/${totalJobId}/enrich`, {
    method: "POST",
    body: new FormData(),
  })
}

export async function getTotalJobSummaryJson(
  totalJobId: string
): Promise<TotalJobSummaryJsonTransport> {
  return apiRequest<TotalJobSummaryJsonTransport>(`/api/v1/total-jobs/${totalJobId}/summary.json`)
}

export async function getTotalJobSummaryMarkdown(
  totalJobId: string
): Promise<ReportMarkdownTransport> {
  return apiRequest<ReportMarkdownTransport>(`/api/v1/total-jobs/${totalJobId}/summary.md`)
}

export async function getTotalJobSandbox(
  totalJobId: string
): Promise<TotalJobSandboxTransport> {
  return apiRequest<TotalJobSandboxTransport>(`/api/v1/total-jobs/${totalJobId}/sandbox`)
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
