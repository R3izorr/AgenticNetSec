"use client"

import { useCallback, useEffect, useMemo, useState } from "react"
import { getJobHistory } from "@/lib/api/analysis"
import { isApiError } from "@/lib/api/client"
import type { JobStatus } from "@/lib/types/analysis"

export interface JobHistorySummary {
  totalJobs: number
  queuedJobs: number
  runningJobs: number
  completedJobs: number
  failedJobs: number
  averageRuntimeSeconds: number | null
  humanReviewRequiredJobs: number
  guardrailClearJobs: number
  recentJobs: JobStatus[]
  riskyJobs: JobStatus[]
}

function buildSummary(jobs: JobStatus[]): JobHistorySummary {
  const runtimeValues = jobs
    .map((job) => job.runtimeSecondsTotal)
    .filter((value): value is number => typeof value === "number" && Number.isFinite(value))

  const sortedByRecency = [...jobs].sort((a, b) => {
    const aValue = new Date(a.updatedAt ?? a.createdAt ?? 0).getTime()
    const bValue = new Date(b.updatedAt ?? b.createdAt ?? 0).getTime()
    return bValue - aValue
  })

  const riskRank = (value: string | null) => {
    if (value === "high") {
      return 3
    }
    if (value === "medium") {
      return 2
    }
    if (value === "low") {
      return 1
    }
    return 0
  }

  const riskyJobs = [...jobs]
    .filter((job) => job.status === "completed")
    .sort((a, b) => {
      const riskDelta = riskRank(b.riskLevel) - riskRank(a.riskLevel)
      if (riskDelta !== 0) {
        return riskDelta
      }
      return (b.confidenceScore ?? 0) - (a.confidenceScore ?? 0)
    })
    .slice(0, 5)

  return {
    totalJobs: jobs.length,
    queuedJobs: jobs.filter((job) => job.status === "queued").length,
    runningJobs: jobs.filter((job) => job.status === "running").length,
    completedJobs: jobs.filter((job) => job.status === "completed").length,
    failedJobs: jobs.filter((job) => job.status === "failed").length,
    averageRuntimeSeconds:
      runtimeValues.length > 0
        ? runtimeValues.reduce((sum, value) => sum + value, 0) / runtimeValues.length
        : null,
    humanReviewRequiredJobs: jobs.filter((job) => job.guardrailState === "Yes").length,
    guardrailClearJobs: jobs.filter((job) => job.guardrailState === "No").length,
    recentJobs: sortedByRecency.slice(0, 6),
    riskyJobs,
  }
}

export function useJobHistory() {
  const [jobs, setJobs] = useState<JobStatus[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await getJobHistory()
      setJobs(response.jobs ?? [])
    } catch (err) {
      const message = isApiError(err)
        ? err.detail || err.message
        : err instanceof Error
          ? err.message
          : "Failed to load job history."
      setJobs([])
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const summary = useMemo(() => buildSummary(jobs), [jobs])

  return {
    jobs,
    loading,
    error,
    refresh,
    summary,
  }
}
