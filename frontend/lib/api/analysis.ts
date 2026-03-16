import { apiRequest } from "@/lib/api/client"
import type {
  ForensicReportTransport,
  JobStatusResponseTransport,
  ReportMarkdownTransport,
  RunMetricsTransport,
} from "@/lib/transport/analysis"
import type { CreateAnalysisInput } from "@/lib/types/analysis"

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
